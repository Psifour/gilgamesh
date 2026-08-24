use super::*;

const MIN_COINFLIPS: usize = 128;
const MIN_DICE_ROLLS: usize = 50;
const MIN_FILE_BYTES: usize = 16;

/// A raw entropy input in one of the canonical encodings. The exact bytes are
/// load-bearing: `seed = sha256(canonical_bytes)`, so encodings are frozen.
/// No `Debug`: variants hold the raw identity entropy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum EntropySource {
    /// ASCII "0"/"1", one char per flip, no separators.
    Coinflips(String),
    /// ASCII "1"-"6", one char per roll, no separators.
    Dice(String),
    /// Raw bytes, bit-exact.
    File(Vec<u8>),
    /// A BIP39 mnemonic. This is an entry convenience, not a new encoding:
    /// the canonical bytes are the decoded entropy, bit-identical to [`Self::File`]
    /// of the same bytes.
    Mnemonic(String),
}

impl EntropySource {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Coinflips(flips) => {
                ensure!(
                    flips.chars().all(|c| c == '0' || c == '1'),
                    "coinflips must contain only '0' and '1' characters"
                );
                ensure!(
                    flips.len() >= MIN_COINFLIPS,
                    "at least {MIN_COINFLIPS} coinflips required, got {}",
                    flips.len()
                );
                Ok(flips.as_bytes().to_vec())
            }
            Self::Dice(rolls) => {
                ensure!(
                    rolls.chars().all(|c| ('1'..='6').contains(&c)),
                    "dice rolls must contain only '1' through '6' characters"
                );
                ensure!(
                    rolls.len() >= MIN_DICE_ROLLS,
                    "at least {MIN_DICE_ROLLS} dice rolls required, got {}",
                    rolls.len()
                );
                Ok(rolls.as_bytes().to_vec())
            }
            Self::File(bytes) => {
                ensure!(
                    bytes.len() >= MIN_FILE_BYTES,
                    "at least {MIN_FILE_BYTES} bytes of file entropy required, got {}",
                    bytes.len()
                );
                Ok(bytes.clone())
            }
            Self::Mnemonic(words) => {
                let mut mnemonic = Mnemonic::parse(words.as_str())
                    .map_err(|err| anyhow!("invalid mnemonic: {err}"))?;
                let entropy = mnemonic.to_entropy();
                mnemonic.zeroize();
                ensure!(
                    entropy.len() >= MIN_FILE_BYTES,
                    "mnemonic encodes {} bytes of entropy, need at least {MIN_FILE_BYTES}",
                    entropy.len()
                );
                Ok(entropy)
            }
        }
    }

    /// Fresh identity entropy from the OS CSPRNG, returned together with its
    /// 24-word BIP39 backup form. The mnemonic re-enters through
    /// [`Self::Mnemonic`] and reproduces the same seed: it is the only backup
    /// of a CSPRNG identity, so it must be displayed and recorded at creation.
    pub fn generate() -> Result<(Self, Zeroizing<String>)> {
        let entropy = Zeroizing::new(random::<32>()?);
        let mut mnemonic = Mnemonic::from_entropy(&*entropy)?;
        let words = Zeroizing::new(mnemonic.to_string());
        mnemonic.zeroize();
        Ok((Self::File(entropy.to_vec()), words))
    }

    /// The canonical 32-byte identity: `sha256(canonical_bytes)`. Display the
    /// seed fingerprint at creation and restore for verification.
    pub fn seed(&self) -> Result<Seed> {
        let mut bytes = self.canonical_bytes()?;
        let seed = Seed::from_bytes(sha256(&bytes));
        bytes.zeroize();
        Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_deterministic_per_encoding() {
        let flips = EntropySource::Coinflips("01".repeat(64));
        assert_eq!(
            flips.seed().unwrap().fingerprint(),
            flips.seed().unwrap().fingerprint()
        );

        let dice = EntropySource::Dice("123456".repeat(10));
        let file = EntropySource::File("123456".repeat(10).into_bytes());
        assert_eq!(
            dice.seed().unwrap().fingerprint(),
            file.seed().unwrap().fingerprint(),
            "identical canonical bytes must produce identical seeds"
        );
    }

    #[test]
    fn invalid_characters_are_rejected() {
        assert!(EntropySource::Coinflips("01 ".repeat(64)).seed().is_err());
        assert!(EntropySource::Dice("1234567".repeat(10)).seed().is_err());
    }

    #[test]
    fn mnemonic_is_a_backup_form_of_raw_bytes() {
        let (source, words) = EntropySource::generate().unwrap();
        assert_eq!(
            source.seed().unwrap().fingerprint(),
            EntropySource::Mnemonic(words.to_string())
                .seed()
                .unwrap()
                .fingerprint(),
            "a mnemonic must reproduce the identity it backs up"
        );

        assert_eq!(words.split_whitespace().count(), 24);
        assert!(
            EntropySource::Mnemonic("not a valid mnemonic".into())
                .seed()
                .is_err()
        );
    }

    #[test]
    fn insufficient_entropy_is_rejected() {
        assert!(EntropySource::Coinflips("01".repeat(63)).seed().is_err());
        assert!(EntropySource::Dice("123456".repeat(8)).seed().is_err());
        assert!(EntropySource::File(vec![0; 15]).seed().is_err());
    }
}
