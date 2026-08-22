// Reference Solana HTLC program for the other leg of the swap. SAME sha256 hashlock
// as the BCH htlc.cash, so revealing the preimage on one chain unlocks the other.
// Reference only: not built/deployed here (no Solana toolchain in this environment).
use solana_program::{
    account_info::{next_account_info, AccountInfo}, entrypoint, entrypoint::ProgramResult,
    hash::hashv, program_error::ProgramError, pubkey::Pubkey, clock::Clock, sysvar::Sysvar,
    program::invoke, system_instruction,
};
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Htlc { pub sender: Pubkey, pub recipient: Pubkey, pub hashlock: [u8;32], pub timeout: i64, pub lamports: u64 }

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Ix { Lock(Htlc), Claim { preimage: Vec<u8> }, Refund }

entrypoint!(process);
pub fn process(_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let state = next_account_info(it)?;       // PDA holding the HTLC + lamports
    match Ix::try_from_slice(data)? {
        Ix::Lock(h) => { h.serialize(&mut &mut state.data.borrow_mut()[..])?; Ok(()) }
        Ix::Claim { preimage } => {
            let h = Htlc::try_from_slice(&state.data.borrow())?;
            // hashlock check: sha256(preimage) == hashlock (matches BCH leg)
            if hashv(&[&preimage]).to_bytes() != h.hashlock { return Err(ProgramError::InvalidArgument); }
            let recipient = next_account_info(it)?;
            if *recipient.key != h.recipient { return Err(ProgramError::IllegalOwner); }
            **state.try_borrow_mut_lamports()? -= h.lamports;
            **recipient.try_borrow_mut_lamports()? += h.lamports;
            Ok(())
        }
        Ix::Refund => {
            let h = Htlc::try_from_slice(&state.data.borrow())?;
            if Clock::get()?.unix_timestamp < h.timeout { return Err(ProgramError::InvalidArgument); }
            let sender = next_account_info(it)?;
            if *sender.key != h.sender { return Err(ProgramError::IllegalOwner); }
            **state.try_borrow_mut_lamports()? -= h.lamports;
            **sender.try_borrow_mut_lamports()? += h.lamports;
            Ok(())
        }
    }
}
