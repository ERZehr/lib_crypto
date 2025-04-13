#!/bin/bash

# Usage: ./run_aes_cbc_test.sh testvector.txt ./aes_binary

VECTOR_FILE="$1"
AES_BIN="$2"

if [[ ! -f "$VECTOR_FILE" || ! -x "$AES_BIN" ]]; then
  echo "Usage: $0 <test_vector_file> <aes_binary>"
  exit 1
fi

TMP_INPUT="input.bin"
TMP_BINOUT="binout.bin"
TMP_OUTPUT="output.hex"
TMP_EXPECTED="expected.hex"
TMP_RESULT="result.log"

rm -f "$TMP_RESULT" "$TMP_INPUT" "$TMP_OUTPUT" "$TMP_EXPECTED" "$TMP_BINOUT"

MODE=""
COUNT=""
KEY=""
IV=""
PLAINTEXT=""
CIPHERTEXT=""
ENC_DEC=""

# Helper: Trim whitespace
trim() {
  echo "$1" | tr -d '[:space:]'
}

# Helper: Check hex string is valid and even-length
is_even_hex() {
  local len=${#1}
  (( len % 2 == 0 ))
}

# Run a test case if all required values are available
run_test_case() {
  if [[ -z "$MODE" || -z "$KEY" || -z "$IV" || -z "$PLAINTEXT" || -z "$CIPHERTEXT" ]]; then
    return
  fi

  if [[ "$MODE" == "ENCRYPT" ]]; then
    INPUT_HEX="$PLAINTEXT"
    EXPECTED_HEX="$CIPHERTEXT"
    ENC_DEC="0"
  elif [[ "$MODE" == "DECRYPT" ]]; then
    INPUT_HEX="$CIPHERTEXT"
    EXPECTED_HEX="$PLAINTEXT"
    ENC_DEC="1"
  else
    echo "[ERROR] Unknown mode at COUNT=$COUNT" >> "$TMP_RESULT"
    return
  fi

  if ! is_even_hex "$KEY" || ! is_even_hex "$IV" || ! is_even_hex "$INPUT_HEX"; then
    echo "[SKIP] COUNT=$COUNT - Invalid hex string (odd length)" >> "$TMP_RESULT"
    return
  fi

  echo -n "$INPUT_HEX" | xxd -r -p > "$TMP_INPUT"
  echo "$EXPECTED_HEX" > "$TMP_EXPECTED"

  ./"$AES_BIN" CFB "$TMP_INPUT" "$KEY" "$IV" "$ENC_DEC" "$TMP_BINOUT"
  if [[ $? -ne 0 ]]; then
    echo "[CRASH] $MODE COUNT=$COUNT - Binary crashed" >> "$TMP_RESULT"
    return
  fi

  xxd -p "$TMP_BINOUT" | tr -d '\n' > "$TMP_OUTPUT"
  ACTUAL=$(cat "$TMP_OUTPUT")
  EXPECTED=$(cat "$TMP_EXPECTED")

  if [[ "$ACTUAL" == "$EXPECTED" ]]; then
    echo "[PASS] $MODE COUNT=$COUNT" >> "$TMP_RESULT"
  else
    echo "[FAIL] $MODE COUNT=$COUNT" >> "$TMP_RESULT"
    echo "       Expected: $EXPECTED" >> "$TMP_RESULT"
    echo "       Got     : $ACTUAL" >> "$TMP_RESULT"
  fi
}

flush_test_if_ready() {
  if [[ -n "$KEY" && -n "$IV" && -n "$PLAINTEXT" && -n "$CIPHERTEXT" ]]; then
    run_test_case
    # Reset after flush
    COUNT=""
    KEY=""
    IV=""
    PLAINTEXT=""
    CIPHERTEXT=""
  fi
}

# Main loop
while IFS= read -r line || [[ -n "$line" ]]; do
  line="$(trim "$line")"

  if [[ "$line" =~ ^\[ENCRYPT\] ]]; then
    flush_test_if_ready
    MODE="ENCRYPT"
    # Reset state between modes to avoid carryover
    COUNT=""
    KEY=""
    IV=""
    PLAINTEXT=""
    CIPHERTEXT=""
    continue
  elif [[ "$line" =~ ^\[DECRYPT\] ]]; then
    flush_test_if_ready
    MODE="DECRYPT"
    COUNT=""
    KEY=""
    IV=""
    PLAINTEXT=""
    CIPHERTEXT=""
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
    flush_test_if_ready
  fi
done < "$VECTOR_FILE"

# Just in case the last test vector wasn't followed by a new one
flush_test_if_ready

cat "$TMP_RESULT"