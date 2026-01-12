use crate::cli::GlobalFlags;
use boxlite::BoxInfo;
use clap::Args;
use comfy_table::{Attribute, Cell, Table, presets};

/// List boxes
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Show all boxes (default just shows running)
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Only show IDs
    #[arg(short, long)]
    pub quiet: bool,
}

pub async fn execute(args: ListArgs, global: &GlobalFlags) -> anyhow::Result<()> {
    let rt = global.create_runtime()?;
    let boxes = rt.list_info().await?;

    if args.quiet {
        for info in boxes {
            if !args.all && !info.status.is_active() {
                continue;
            }
            println!("{}", info.id);
        }
        return Ok(());
    }

    print_info(boxes, args.all);

    Ok(())
}

fn print_info(boxes: Vec<BoxInfo>, all: bool) {
    let mut table = Table::new();
    table
        .load_preset(presets::UTF8_NO_BORDERS)
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("ID").add_attribute(Attribute::Bold),
        Cell::new("IMAGE").add_attribute(Attribute::Bold),
        Cell::new("STATUS").add_attribute(Attribute::Bold),
        Cell::new("CREATED").add_attribute(Attribute::Bold),
        Cell::new("NAMES").add_attribute(Attribute::Bold),
    ]);

    for info in boxes {
        if !all && !info.status.is_active() {
            continue;
        }

        let created = info.created_at.format("%Y-%m-%d %H:%M:%S").to_string();

        table.add_row(vec![
            info.id.to_string(),
            info.image.clone(),
            format!("{:?}", info.status),
            created,
            info.name.clone().unwrap_or_else(|| "".to_string()),
        ]);
    }

    println!("{table}");
}
