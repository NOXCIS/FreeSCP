//! `freescp shell` — interactive SFTP-style shell.

use std::io::{BufRead, IsTerminal};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use freescp_core::{client_factory, Protocol, SftpClient};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::cli::{ConnectionArgs, ShellArgs};
use crate::commands::{cancel_cb, cancel_flag, remote_file_name, CommonArgs, TransferProgress};
use crate::output;
use crate::session;

/// Whether the REPL should keep going after a command.
enum Control {
    Continue,
    Exit,
}

struct ShellState {
    conn: ConnectionArgs,
    target: Option<String>,
    client: Option<Box<dyn SftpClient>>,
    remote_cwd: String,
    local_cwd: PathBuf,
}

impl ShellState {
    fn new(conn: ConnectionArgs, target: Option<String>) -> Result<Self> {
        Ok(Self {
            conn,
            target,
            client: None,
            remote_cwd: ".".to_string(),
            local_cwd: std::env::current_dir()?,
        })
    }

    async fn open(&mut self, raw: Option<&str>) -> Result<()> {
        if let Some(raw) = raw {
            self.target = Some(raw.to_string());
        }
        let raw = self
            .target
            .clone()
            .ok_or_else(|| anyhow!("no target; usage: open [user@]host[:port]"))?;
        let target = session::parse_target(&raw)?;
        let protocol = session::resolved_protocol(&self.conn, Protocol::Sftp);
        if protocol == Protocol::Telnet {
            bail!("telnet is an interactive console; run `freescp console {raw}` instead");
        }

        let options = session::prepare(&self.conn, &target, protocol)?;
        let client = client_factory::create_connected_client(&options).await?;
        if let Some(mut previous) = self.client.take() {
            let _ = previous.disconnect().await;
        }
        self.client = Some(client);
        self.remote_cwd = ".".to_string();
        println!("Connected to {}", session::describe(&options));
        Ok(())
    }

    async fn close(&mut self) {
        if let Some(mut client) = self.client.take() {
            let _ = client.disconnect().await;
        }
        self.remote_cwd = ".".to_string();
    }

    fn client(&mut self) -> Result<&mut Box<dyn SftpClient>> {
        self.client
            .as_mut()
            .ok_or_else(|| anyhow!("not connected; use `open [user@]host[:port]`"))
    }

    fn prompt(&self) -> String {
        if self.client.is_some() {
            format!("freescp:{}> ", self.remote_cwd)
        } else {
            "freescp> ".to_string()
        }
    }

    /// Remote path resolution against the shell's current directory.
    fn resolve(&self, raw: &str) -> String {
        join_remote(&self.remote_cwd, raw)
    }

    /// Local path resolution against the shell's local directory, with `~`
    /// expansion.
    fn local_path(&self, raw: &str) -> PathBuf {
        let expanded = if raw == "~" {
            dirs::home_dir().unwrap_or_else(|| PathBuf::from(raw))
        } else if let Some(rest) = raw.strip_prefix("~/") {
            dirs::home_dir()
                .map(|home| home.join(rest))
                .unwrap_or_else(|| PathBuf::from(raw))
        } else {
            PathBuf::from(raw)
        };
        if expanded.is_absolute() {
            normalize_path(&expanded)
        } else {
            normalize_path(&self.local_cwd.join(expanded))
        }
    }

    async fn execute(&mut self, common: &CommonArgs, line: &str) -> Result<Control> {
        let mut parts = split_args(line);
        if parts.is_empty() {
            return Ok(Control::Continue);
        }
        let command = parts.remove(0);
        let args = parts;

        match command.as_str() {
            "help" | "?" => print_help(),
            "exit" | "quit" | "bye" => return Ok(Control::Exit),
            "open" => self.open(args.first().map(String::as_str)).await?,
            "close" => self.close().await,
            "cd" => {
                self.change_remote_dir(args.first().map(String::as_str))
                    .await?
            }
            "pwd" => println!("{}", self.remote_cwd),
            "ls" => self.list(common, args.first().map(String::as_str)).await?,
            "get" => self.get(common, &args).await?,
            "put" => self.put(common, &args).await?,
            "mkdir" => self.mkdir(&args).await?,
            "rm" => self.rm(&args).await?,
            "mv" => self.mv(&args).await?,
            "lcd" => self.change_local_dir(args.first().map(String::as_str))?,
            "lpwd" => println!("{}", self.local_cwd.display()),
            other => bail!("unknown command '{other}'; type `help` for the command list"),
        }
        Ok(Control::Continue)
    }

    async fn change_remote_dir(&mut self, raw: Option<&str>) -> Result<()> {
        let raw = raw.unwrap_or(".");
        let path = self.resolve(raw);
        match self.client()?.exists(&path).await? {
            Some(true) => self.remote_cwd = path,
            Some(false) => bail!("not a directory: {raw}"),
            None => bail!("no such directory: {raw}"),
        }
        Ok(())
    }

    fn change_local_dir(&mut self, raw: Option<&str>) -> Result<()> {
        let path = self.local_path(raw.unwrap_or("~"));
        if !path.is_dir() {
            bail!("no such local directory: {}", path.display());
        }
        self.local_cwd = path;
        Ok(())
    }

    async fn list(&mut self, _common: &CommonArgs, raw: Option<&str>) -> Result<()> {
        let path = self.resolve(raw.unwrap_or("."));
        let entries = self.client()?.list(&path).await?;
        output::print_listing(&entries, false)?;
        Ok(())
    }

    async fn get(&mut self, common: &CommonArgs, args: &[String]) -> Result<()> {
        let remote_arg = args
            .first()
            .ok_or_else(|| anyhow!("usage: get <remote> [local]"))?;
        let remote = self.resolve(remote_arg);
        let local_name = match args.get(1) {
            Some(local) => local.clone(),
            None => remote_file_name(remote_arg)?,
        };
        let local = self.local_path(&local_name);
        let local_display = local.display().to_string();

        let progress = TransferProgress::new(&local_display, common.quiet);
        let flag = cancel_flag();
        let outcome = self
            .client()?
            .get(
                &remote,
                &local_display,
                progress.callback(),
                Some(cancel_cb(&flag)),
                false,
            )
            .await;
        match outcome {
            Ok(()) => {
                progress.finish(
                    common.quiet,
                    &format!("downloaded {remote} -> {local_display}"),
                );
                Ok(())
            }
            Err(err) => {
                progress.abort();
                Err(err.into())
            }
        }
    }

    async fn put(&mut self, common: &CommonArgs, args: &[String]) -> Result<()> {
        let local_arg = args
            .first()
            .ok_or_else(|| anyhow!("usage: put <local> [remote]"))?;
        let local = self.local_path(local_arg);
        if !local.is_file() {
            bail!("no such local file: {}", local.display());
        }
        let remote = match args.get(1) {
            Some(remote) => self.resolve(remote),
            None => {
                let name = local
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| anyhow!("cannot derive a remote file name; pass one"))?;
                self.resolve(name)
            }
        };
        let local_display = local.display().to_string();

        let progress = TransferProgress::new(&remote, common.quiet);
        let flag = cancel_flag();
        let outcome = self
            .client()?
            .put(
                &local_display,
                &remote,
                progress.callback(),
                Some(cancel_cb(&flag)),
                false,
            )
            .await;
        match outcome {
            Ok(()) => {
                progress.finish(
                    common.quiet,
                    &format!("uploaded {local_display} -> {remote}"),
                );
                Ok(())
            }
            Err(err) => {
                progress.abort();
                Err(err.into())
            }
        }
    }

    async fn mkdir(&mut self, args: &[String]) -> Result<()> {
        let raw = args.first().ok_or_else(|| anyhow!("usage: mkdir <path>"))?;
        let path = self.resolve(raw);
        self.client()?.mkdir(&path, 0o755).await?;
        Ok(())
    }

    async fn rm(&mut self, args: &[String]) -> Result<()> {
        let raw = args.first().ok_or_else(|| anyhow!("usage: rm <path>"))?;
        let path = self.resolve(raw);
        match self.client()?.exists(&path).await? {
            None => bail!("no such file or directory: {raw}"),
            Some(true) => self.client()?.remove_dir(&path).await?,
            Some(false) => self.client()?.remove_file(&path).await?,
        }
        Ok(())
    }

    async fn mv(&mut self, args: &[String]) -> Result<()> {
        if args.len() < 2 {
            bail!("usage: mv <from> <to>");
        }
        let from = self.resolve(&args[0]);
        let to = self.resolve(&args[1]);
        self.client()?.rename(&from, &to, true).await?;
        Ok(())
    }
}

pub async fn run(common: &CommonArgs, args: &ShellArgs) -> Result<u8> {
    let interactive = std::io::stdin().is_terminal();
    let mut state = ShellState::new(args.conn.clone(), args.target.clone())?;

    if state.target.is_some() {
        if let Err(err) = state.open(None).await {
            if !interactive {
                return Err(err);
            }
            eprintln!("freescp: {err:#}");
        }
    }

    if interactive {
        repl(common, &mut state).await
    } else {
        piped(common, &mut state).await
    }
}

async fn repl(common: &CommonArgs, state: &mut ShellState) -> Result<u8> {
    let mut editor = DefaultEditor::new()?;
    let history = history_path();
    if let Some(path) = &history {
        let _ = editor.load_history(path);
    }

    println!("FreeSCP shell — type `help` for commands, `exit` to quit");
    loop {
        match editor.readline(&state.prompt()) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = editor.add_history_entry(line.as_str());
                match state.execute(common, &line).await {
                    Ok(Control::Continue) => {}
                    Ok(Control::Exit) => break,
                    Err(err) => eprintln!("freescp: {err:#}"),
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("freescp: input error: {err}");
                break;
            }
        }
    }

    if let Some(path) = &history {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = editor.save_history(path);
    }
    state.close().await;
    Ok(0)
}

async fn piped(common: &CommonArgs, state: &mut ShellState) -> Result<u8> {
    let stdin = std::io::stdin();
    let mut code = 0;
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match state.execute(common, line).await {
            Ok(Control::Continue) => {}
            Ok(Control::Exit) => break,
            Err(err) => {
                eprintln!("freescp: {err:#}");
                code = 1;
                break;
            }
        }
    }
    state.close().await;
    Ok(code)
}

fn print_help() {
    println!(
        "Commands:\n\
         \x20 open [user@]host[:port]   connect to a server\n\
         \x20 close                     disconnect\n\
         \x20 cd [path]                 change the remote directory\n\
         \x20 pwd                       print the remote directory\n\
         \x20 ls [path]                 list a remote directory\n\
         \x20 get <remote> [local]      download a file\n\
         \x20 put <local> [remote]      upload a file\n\
         \x20 mkdir <path>              create a remote directory\n\
         \x20 rm <path>                 remove a remote file or empty directory\n\
         \x20 mv <from> <to>            rename or move a remote path\n\
         \x20 lcd [path]                change the local directory\n\
         \x20 lpwd                      print the local directory\n\
         \x20 help                      show this help\n\
         \x20 exit                      quit"
    );
}

fn history_path() -> Option<PathBuf> {
    let base = dirs::state_dir().or_else(dirs::data_local_dir)?;
    Some(base.join("freescp").join("shell_history"))
}

/// Joins a remote path against the shell's current directory.
fn join_remote(cwd: &str, path: &str) -> String {
    if path.is_empty() {
        return cwd.to_string();
    }
    if path.starts_with('/') {
        return path.to_string();
    }
    match cwd {
        "" | "." => path.to_string(),
        "/" => format!("/{path}"),
        base => format!("{base}/{path}"),
    }
}

/// Lexically normalizes a local path (collapses `.` and `..`).
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Splits a command line into arguments, honoring single and double quotes.
fn split_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for ch in line.chars() {
        match (ch, quote) {
            ('"' | '\'', None) => {
                quote = Some(ch);
                started = true;
            }
            (c, Some(open)) if c == open => {
                quote = None;
                started = true;
            }
            (c, None) if c.is_whitespace() => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (c, _) => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        args.push(current);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_arguments() {
        assert_eq!(split_args("ls -l"), vec!["ls", "-l"]);
        assert_eq!(
            split_args("get \"my file.txt\" 'other name'"),
            vec!["get", "my file.txt", "other name"]
        );
        assert_eq!(split_args("   ").len(), 0);
        assert_eq!(split_args("put '' x"), vec!["put", "", "x"]);
    }

    #[test]
    fn joins_remote_paths() {
        assert_eq!(join_remote(".", "file.txt"), "file.txt");
        assert_eq!(join_remote(".", "/abs/file.txt"), "/abs/file.txt");
        assert_eq!(join_remote("/home/user", "sub"), "/home/user/sub");
        assert_eq!(join_remote("/", "sub"), "/sub");
        assert_eq!(join_remote("/home/user", ""), "/home/user");
    }

    #[test]
    fn normalizes_local_paths() {
        assert_eq!(
            normalize_path(Path::new("/a/./b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(normalize_path(Path::new("a/b/../../c")), PathBuf::from("c"));
        assert_eq!(normalize_path(Path::new("../a")), PathBuf::from("../a"));
    }
}
