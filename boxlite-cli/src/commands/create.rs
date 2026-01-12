use crate::cli::{GlobalFlags, ResourceFlags};
use boxlite::{BoxOptions, RootfsSpec};
use clap::Args;

/// Create a new box
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Image to create from
    #[arg(index = 1)]
    pub image: String,

    /// Assign a name to the box
    #[arg(long)]
    pub name: Option<String>,

    /// Automatically remove the box when it exits
    #[arg(long)]
    pub rm: bool,

    /// Set environment variables
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Working directory inside the box
    #[arg(short = 'w', long = "workdir")]
    pub workdir: Option<String>,

    #[command(flatten)]
    pub resource: ResourceFlags,
}

pub async fn execute(args: CreateArgs, global: &GlobalFlags) -> anyhow::Result<()> {
    let rt = global.create_runtime()?;
    let box_options = args.to_box_options();

    let litebox = rt.create(box_options, args.name).await?;
    println!("{}", litebox.id());

    Ok(())
}

impl CreateArgs {
    fn to_box_options(&self) -> BoxOptions {
        let mut options = BoxOptions::default();
        self.resource.apply_to(&mut options);
        options.auto_remove = self.rm;
        options.working_dir = self.workdir.clone();
        crate::cli::apply_env_vars(&self.env, &mut options);
        options.rootfs = RootfsSpec::Image(self.image.clone());
        options
    }
}
