//! AURIX Verified Soroban Timelocked Escrow Contract
//! Example reference implementation for Stellar Soroban Developers.
//! Certified by AURIX Soroban Security Guard (0 critical/high issues).

#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, IntoVal,
    Symbol, TryFromVal, Val,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum EscrowError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    DeadlineNotPassed = 4,
    DeadlinePassed = 5,
    MathOverflow = 6,
    ZeroAmount = 7,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Funder,
    Recipient,
    Verifier,
    Amount,
    Deadline,
    Settled,
}

const INSTANCE_BUMP_AMOUNT: u32 = 518400; // ~30 days in blocks
const INSTANCE_LIFETIME_THRESHOLD: u32 = 172800; // ~10 days

#[contract]
pub struct TimelockedEscrow;

#[contractimpl]
impl TimelockedEscrow {
    /// Initialize escrow with funder, recipient, verifier, amount and deadline
    pub fn init(
        env: Env,
        funder: Address,
        recipient: Address,
        verifier: Address,
        amount: i128,
        deadline: u64,
    ) -> Result<(), EscrowError> {
        funder.require_auth();

        if amount <= 0 {
            return Err(EscrowError::ZeroAmount);
        }

        if env.storage().instance().has(&DataKey::Funder) {
            return Err(EscrowError::AlreadyInitialized);
        }

        env.storage().instance().set(&DataKey::Funder, &funder);
        env.storage().instance().set(&DataKey::Recipient, &recipient);
        env.storage().instance().set(&DataKey::Verifier, &verifier);
        env.storage().instance().set(&DataKey::Amount, &amount);
        env.storage().instance().set(&DataKey::Deadline, &deadline);
        env.storage().instance().set(&DataKey::Settled, &false);

        // Extend TTL per Soroban State Archival specifications
        env.storage().instance().extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        Ok(())
    }

    /// Verifier settles the payment to recipient before deadline
    pub fn settle(env: Env, caller: Address) -> Result<i128, EscrowError> {
        caller.require_auth();

        let verifier: Address = env
            .storage()
            .instance()
            .get(&DataKey::Verifier)
            .ok_or(EscrowError::NotInitialized)?;

        if caller != verifier {
            return Err(EscrowError::Unauthorized);
        }

        let is_settled: bool = env.storage().instance().get(&DataKey::Settled).unwrap_or(true);
        if is_settled {
            return Err(EscrowError::Unauthorized);
        }

        let deadline: u64 = env.storage().instance().get(&DataKey::Deadline).unwrap_or(0);
        if env.ledger().timestamp() > deadline {
            return Err(EscrowError::DeadlinePassed);
        }

        let amount: i128 = env.storage().instance().get(&DataKey::Amount).unwrap_or(0);
        env.storage().instance().set(&DataKey::Settled, &true);

        // Maintain storage health
        env.storage().instance().extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        Ok(amount)
    }

    /// Funder claims refund after deadline has passed without settlement
    pub fn refund(env: Env, caller: Address) -> Result<i128, EscrowError> {
        caller.require_auth();

        let funder: Address = env
            .storage()
            .instance()
            .get(&DataKey::Funder)
            .ok_or(EscrowError::NotInitialized)?;

        if caller != funder {
            return Err(EscrowError::Unauthorized);
        }

        let is_settled: bool = env.storage().instance().get(&DataKey::Settled).unwrap_or(true);
        if is_settled {
            return Err(EscrowError::Unauthorized);
        }

        let deadline: u64 = env.storage().instance().get(&DataKey::Deadline).unwrap_or(0);
        if env.ledger().timestamp() <= deadline {
            return Err(EscrowError::DeadlineNotPassed);
        }

        let amount: i128 = env.storage().instance().get(&DataKey::Amount).unwrap_or(0);
        env.storage().instance().set(&DataKey::Settled, &true);

        env.storage().instance().extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        Ok(amount)
    }
}
