# Architecture-of-security-for-motorsport
Document of my security systems 

# GT4 Secure Radio & Data Transmission Architecture
Autor: Kacper Magiera — Secure Comms Architect / System Safety Specialist

## 1. Cel systemu

- System transmisji danych dla pojazdów GT4.
- Real‑time, niskie opóźnienia.
- Integralność, anti‑replay, odporność na zakłócenia RF.
- Kanały: paliwo, koła, radio kierowcy, radio zespołu, radio kierownika.

---

## 2. Struktura ramki

+---------+------+---------+-----------+-----------+----------------+
| HEADER  | TYPE |   SEQ   |  NONCE    | PAYLOAD   | MAC + CRC      |
+---------+------+---------+-----------+-----------+----------------+

- HEADER: 2B, stałe `0xAA 0xBB`
- TYPE: 1B
  - 0x01 – paliwo
  - 0x02 – koła
  - 0x03 – radio kierowcy
  - 0x04 – radio zespołu
  - 0x05 – radio kierownika
- SEQ: 2B, `0x0000` → `0xFFFF`, +1 per ramka
- NONCE: 3B, losowy numer sesji
- PAYLOAD: 0–32B, zależny od TYPE
- MAC: 8B, HMAC‑SHA256 (truncated)
- CRC: 2B, CRC‑16 (0x1021)

MAC input:
HEADER || TYPE || SEQ || NONCE || PAYLOAD

CRC input:
HEADER || TYPE || SEQ || NONCE || PAYLOAD || MAC

---

## 3. Klucze

- MasterKey: 256 bit, ECU + pitwall, nigdy nie transmitowany.
- RotationKey: 128 bit
  - RotationKey = HMAC(MasterKey, NONCE)
  - Rotacja: co 30 min, pit‑stop, anomalia RF.
- SessionKey:
  - SessionKey = HMAC(RotationKey, NONCE)

MAC(SessionKey, HEADER || TYPE || SEQ || NONCE || PAYLOAD)

---

## 4. Anti‑Replay

Odrzuć ramkę, jeśli:

- SEQ ≠ lastSEQ + 1
- NONCE ≠ currentNONCE
- MAC invalid
- CRC invalid
- TYPE niedozwolony dla kanału

Bufor ostatnich 32 SEQ, wykrywanie duplikatów, opóźnień > 200 ms.

---

## 5. Warstwy bezpieczeństwa

1. Warstwa integralności:
   - MAC + CRC

2. Warstwa SEQ/NONCE:
   - Chroni przed replay, manipulacją.

3. Warstwa sanity‑check payloadu:
   - Paliwo nie rośnie skokowo.
   - Temp opon nie spada o 20°C w 1 ms.
   - Radio nie ma pustego payloadu.

---

## 6. Pseudokod odbiornika

```cpp
struct Frame {
    uint16_t header;   // 0xAABB
    uint8_t  type;     // 0x01..0x05
    uint16_t seq;      // 0..65535
    uint8_t  nonce[3]; // 24-bit
    uint8_t  payload[32];
    uint8_t  mac[8];
    uint16_t crc;
};

bool CRC_OK(const Frame& f);
bool MAC_OK(const Frame& f, const uint8_t* sessionKey);
bool TYPE_ALLOWED(uint8_t type);
void ValidatePayload(uint8_t type, const uint8_t* payload);
void Process(const Frame& f);

uint16_t lastSEQ = 0;
uint8_t  currentNONCE[3];
uint8_t  sessionKey[32];

void HandleFrame(const Frame& f) {
    if (!CRC_OK(f)) return;
    if (!MAC_OK(f, sessionKey)) return;
    if (!TYPE_ALLOWED(f.type)) return;

    if (f.seq != (uint16_t)(lastSEQ + 1)) return;

    if (memcmp(f.nonce, currentNONCE, 3) != 0) return;

    ValidatePayload(f.type, f.payload);

    lastSEQ = f.seq;
    Process(f);
}
void InitSession(const uint8_t* masterKey) {
    uint8_t nonce[3];
    GenerateRandomNonce(nonce, 3);

    memcpy(currentNONCE, nonce, 3);

    uint8_t rotationKey[16];
    HMAC_SHA256_trunc(masterKey, 32, nonce, 3, rotationKey, 16);

    HMAC_SHA256_trunc(rotationKey, 16, nonce, 3, sessionKey, 32);

    lastSEQ = 0;
}
