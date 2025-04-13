#!/bin/bash

# Usage: ./run_aes_gcm_test.sh testvector.txt ./aes_binary

VECTOR_FILE="$1"
AES_BIN="$2"

if [[ ! -f "$VECTOR_FILE" || ! -x "$AES_BIN" ]]; then
  echo "Usage: $0 <test_vector_file> <aes_binary>"
  exit 1
fi

TMP_INPUT="input.bin"
TMP_OUTPUT="output.hex"
TMP_EXPECTED="expected.hex"
TMP_RESULT="result.log"
TMP_CIPHERS="cipher_outputs.tmp"

rm -f "$TMP_RESULT" "$TMP_INPUT" "$TMP_OUTPUT" "$TMP_EXPECTED" "$TMP_CIPHERS"

MODE=""
COUNT=""
KEY=""
IV=""
PT=""
AAD=""
CT=""
TAG=""
ENC_DEC=""
ENCRYPTED_RESULT=""
COUNTER=""

# Helper: Trim spaces
trim() {
  echo "$1" | tr -d '[:space:]'
}

# Helper: Check hex string even length
is_even_hex() {
  local len=${#1}
  (( len % 2 == 0 ))
}

while IFS= read -r line || [ -n "$line" ]; do
  line="$(trim "$line")"

  if [[ "$line" =~ ^\[ENCRYPT\] ]]; then
    MODE="ENCRYPT"
    continue
  elif [[ "$line" =~ ^\[DECRYPT\] ]]; then
    MODE="DECRYPT"
    continue
  fi

  if [[ "$line" =~ ^COUNT ]]; then
    COUNT="${line#*=}"
    COUNT="$(trim "$COUNT")"
  elif [[ "$line" =~ ^Key ]]; then
    KEY="${line#*=}"
    KEY="$(trim "$KEY")"
  elif [[ "$line" =~ ^IV ]]; then
    IV="${line#*=}"
    IV="$(trim "$IV")"
  elif [[ "$line" =~ ^PT ]]; then
    PT="${line#*=}"
    PT="$(trim "$PT")"
  elif [[ "$line" =~ ^AAD ]]; then
    AAD="${line#*=}"
    AAD="$(trim "$AAD")"
  elif [[ "$line" =~ ^CT ]]; then
    CT="${line#*=}"
    CT="$(trim "$CT")"
  elif [[ "$line" =~ ^Tag ]]; then
    TAG="${line#*=}"
    TAG="$(trim "$TAG")"

    MODE=ENCRYPT
    # Handle encryption or decryption
    if [[ "$MODE" == "ENCRYPT" ]]; then
      INPUT_HEX="$PT"
      EXPECTED_HEX="$CT"
      ENC_DEC="0"
    elif [[ "$MODE" == "DECRYPT" ]]; then
      INPUT_HEX="$CT"
      EXPECTED_HEX="$PT"
      ENC_DEC="1"
    else
      echo "[ERROR] Unknown mode at COUNT=$COUNT"
      continue
    fi

    if ! is_even_hex "$KEY" || ! is_even_hex "$INPUT_HEX" || ! is_even_hex "$IV"; then
      echo "[SKIP] COUNT=$COUNT - Invalid hex string (odd length)"
      continue
    fi

    echo -n "$INPUT_HEX" | xxd -r -p > "$TMP_INPUT"
    echo "$EXPECTED_HEX" > "$TMP_EXPECTED"

    # Prepare counter (set to default if empty)
    COUNTER="${COUNTER:-"00000001"}"
    COUNTER_HEX="$(xxd -p <<< "$COUNTER")"

    # Handle GCM mode, separate function calls for encryption and decryption
    echo "Running: $AES_BIN GCM $TMP_INPUT $KEY $IV $ENC_DEC -aad $AAD -tag $TAG"
    ./main GCM "$TMP_INPUT" "$KEY" "$IV" "$ENC_DEC" "-aad" "$AAD" "-tag" "$TAG" > "$TMP_RESULT"

    if [[ $? -ne 0 ]]; then
      echo "[CRASH] $MODE COUNT=$COUNT - Binary crashed" >> "$TMP_RESULT"
      continue
    fi

    # Check the result against the expected output
    xxd -p "$TMP_INPUT" | tr -d '\n' > "$TMP_OUTPUT"
    ACTUAL=$(cat "$TMP_OUTPUT")

    EXPECTED=$(cat "$TMP_EXPECTED")

    if [[ "$ACTUAL" == "$EXPECTED" ]]; then
      echo "[PASS] $MODE COUNT=$COUNT" >> "$TMP_RESULT"
    else
      echo "[FAIL] $MODE COUNT=$COUNT" >> "$TMP_RESULT"
      echo "       Expected: $EXPECTED" >> "$TMP_RESULT"
      echo "       Got     : $ACTUAL" >> "$TMP_RESULT"
    fi
  fi
done < "$VECTOR_FILE"

cat "$TMP_RESULT"