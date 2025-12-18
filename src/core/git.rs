//! Git repository cloning

use anyhow::{Result, Context};
use git2::{Repository, FetchOptions, RemoteCallbacks, Progress};
use std::path::PathBuf;
use tracing::{info, debug};

/// Repository cloner using git2
pub struct RepoCloner {
    /// Temporary directory for cloned repos
    temp_dir: PathBuf,
}

impl RepoCloner {
    /// Create a new repo cloner
    pub fn new() -> Self {
        let temp_dir = std::env::temp_dir().join("hyperion_repos");
        Self { temp_dir }
    }

    /// Clone a repository from URL
    pub async fn clone(&self, url: &str) -> Result<PathBuf> {
        // Create temp directory if it doesn't exist
        std::fs::create_dir_all(&self.temp_dir)?;

        // Generate unique directory name from URL
        let repo_name = self.extract_repo_name(url);
        let timestamp = chrono::Utc::now().timestamp();
        let dest_dir = self.temp_dir.join(format!("{}_{}", repo_name, timestamp));

        info!("Cloning {} to {:?}", url, dest_dir);

        // Setup callbacks for progress
        let mut callbacks = RemoteCallbacks::new();
        callbacks.transfer_progress(|progress: Progress| {
            let received = progress.received_objects();
            let total = progress.total_objects();
            if total > 0 && received % 100 == 0 {
                debug!("Cloning: {}/{} objects", received, total);
            }
            true
        });

        // Setup fetch options
        let mut fetch_opts = FetchOptions::new();
        fetch_opts.remote_callbacks(callbacks);

        // Build clone options
        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(fetch_opts);

        // Clone the repository
        builder
            .clone(url, &dest_dir)
            .context("Failed to clone repository")?;

        info!("Success Repository cloned successfully");
        Ok(dest_dir)
    }

    /// Clone with specific branch
    pub async fn clone_branch(&self, url: &str, branch: &str) -> Result<PathBuf> {
        let repo_name = self.extract_repo_name(url);
        let timestamp = chrono::Utc::now().timestamp();
        let dest_dir = self.temp_dir.join(format!("{}_{}_{}", repo_name, branch, timestamp));

        std::fs::create_dir_all(&self.temp_dir)?;

        let mut builder = git2::build::RepoBuilder::new();
        builder.branch(branch);
        
        builder
            .clone(url, &dest_dir)
            .context("Failed to clone repository branch")?;

        Ok(dest_dir)
    }

    /// Clone at specific commit
    pub async fn clone_commit(&self, url: &str, commit: &str) -> Result<PathBuf> {
        let dest_dir = self.clone(url).await?;
        
        // Checkout specific commit
        let repo = Repository::open(&dest_dir)?;
        let oid = git2::Oid::from_str(commit)?;
        let commit_obj = repo.find_commit(oid)?;
        
        repo.checkout_tree(commit_obj.as_object(), None)?;
        repo.set_head_detached(oid)?;

        Ok(dest_dir)
    }

    /// Extract repository name from URL
    fn extract_repo_name(&self, url: &str) -> String {
        url.trim_end_matches(".git")
            .split('/')
            .last()
            .unwrap_or("repo")
            .to_string()
    }

    /// Cleanup cloned repositories
    pub fn cleanup(&self) -> Result<()> {
        if self.temp_dir.exists() {
            std::fs::remove_dir_all(&self.temp_dir)?;
        }
        Ok(())
    }

    /// Get list of cloned repos
    pub fn list_cloned(&self) -> Result<Vec<PathBuf>> {
        let mut repos = Vec::new();
        
        if self.temp_dir.exists() {
            for entry in std::fs::read_dir(&self.temp_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    repos.push(entry.path());
                }
            }
        }
        
        Ok(repos)
    }
}

impl Default for RepoCloner {
    fn default() -> Self {
        Self::new()
    }
}
