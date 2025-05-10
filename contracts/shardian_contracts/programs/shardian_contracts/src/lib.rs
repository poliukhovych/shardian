use anchor_lang::prelude::*;

declare_id!("AtvDok3PwVJD9ojvyYojhBPp6dsqvLYdX8c3sAiWx3dX");

#[program]
pub mod shardian_contracts {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
