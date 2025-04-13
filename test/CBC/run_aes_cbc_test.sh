#!/bin/bash

# Usage: ./run_aes_cbc_test.sh testvector.txt ./aes_binary

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

rm -f "$TMP_RESULT" "$TMP_INPUT" "$TMP_OUTPUT" "$TMP_EXPECTED"

MODE=""
COUNT=""
KEY=""
IV=""
PLAINTEXT=""
CIPHERTEXT=""
ENC_DEC=""

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
  elif [[ "$line" =~ ^KEY ]]; then
    KEY="${line#*=}"
    KEY="$(trim "$KEY")"
  elif [[ "$line" =~ ^IV ]]; then
    IV="${line#*=}"
    IV="$(trim "$IV")"
  elif [[ "$line" =~ ^PLAINTEXT ]]; then
    PLAINTEXT="${line#*=}"
    PLAINTEXT="$(trim "$PLAINTEXT")"
  elif [[ "$line" =~ ^CIPHERTEXT ]]; then
    CIPHERTEXT="${line#*=}"
    CIPHERTEXT="$(trim "$CIPHERTEXT")"

    # Determine input/output for this test case
    if [[ "$MODE" == "ENCRYPT" ]]; then
      INPUT_HEX="$PLAINTEXT"
      EXPECTED_HEX="$CIPHERTEXT"
      ENC_DEC="0"
    elif [[ "$MODE" == "DECRYPT" ]]; then
      INPUT_HEX="$CIPHERTEXT"
      EXPECTED_HEX="$PLAINTEXT"
      ENC_DEC="1"
    else
      echo "[ERROR] Unknown mode at COUNT=$COUNT"
      continue
    fi

    if ! is_even_hex "$KEY" || ! is_even_hex "$IV" || ! is_even_hex "$INPUT_HEX"; then
      echo "[SKIP] COUNT=$COUNT - Invalid hex string (odd length)"
      continue
    fi

    echo -n "$INPUT_HEX" | xxd -r -p > "$TMP_INPUT"
    echo "$EXPECTED_HEX" > "$TMP_EXPECTED"

    echo "Running: $AES_BIN CBC $TMP_INPUT $KEY $IV $ENC_DEC"
    ./"$AES_BIN" CBC "$TMP_INPUT" "$KEY" "$IV" "$ENC_DEC"
    if [[ $? -ne 0 ]]; then
      echo "[CRASH] $MODE COUNT=$COUNT - Binary crashed" >> "$TMP_RESULT"
      continue
    fi

    xxd -p "$TMP_INPUT" | tr -d '\n' > "$TMP_OUTPUT"
    ACTUAL=$(cat "$TMP_OUTPUT")

    # Strip padding (last 16 bytes) for both modes before comparison
    if [[ "${#ACTUAL}" -ge 32 ]]; then
      ACTUAL="${ACTUAL:0:-32}"
    fi

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