# Noise_XX_25519_ChaChaPoly_BLAKE2b — ProVerif Results

## Kurulum

```bash
# ProVerif
paru -S proverif

# Noise Explorer modelleri
/tmp/noiseexplorer/models/XX.noise.{active,passive}.pv
```

## Komutlar

```bash
# Active attacker
proverif /tmp/noiseexplorer/models/XX.noise.active.pv 2>&1 | tee tests/proverif/XX_active.txt

# Passive attacker
proverif /tmp/noiseexplorer/models/XX.noise.passive.pv 2>&1 | tee tests/proverif/XX_passive.txt
```

## Sonuçlar

### Passive Attacker (beklenen)
- Message C (→s,se): authentication ✅, secrecy ✅, forward secrecy ✅
- Message D (←data): authentication ✅, secrecy ✅, forward secrecy ✅
- Message E (→data): authentication ✅, secrecy ✅, forward secrecy ✅

### Active Attacker (beklenen)
- XX pattern active attack'e karşı data phase authentication sağlamaz
- Bu Noise_XX specification'ın tasarım limitidir

## Dosyalar
- `XX_active.txt` — Active attacker ProVerif çıktısı
- `XX_passive.txt` — Passive attacker ProVerif çıktısı
