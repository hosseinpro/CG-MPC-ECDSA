use structopt::StructOpt;

use cli::xax21_party_one::Opt as XAXPartyOneOpt;
use cli::xax21_party_two::Opt as XAXPartyTwoOpt;

#[derive(Debug, StructOpt)]
pub enum Opt {
    XAXPartyOne(XAXPartyOneOpt),
    XAXPartyTwo(XAXPartyTwoOpt),
}

impl Opt {
    pub async fn execute(self) {
        match self {
            Self::XAXPartyOne(opt) => opt.execute().await,
            Self::XAXPartyTwo(opt) => opt.execute().await,
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "mpc-ecdsa", about = "mpc-ecdsa demo")]
struct Arguments {
    #[structopt(subcommand)]
    opt: Opt,
}
#[async_std::main]
async fn main() {
    let args: Arguments = Arguments::from_args();
    args.opt.execute().await
}
