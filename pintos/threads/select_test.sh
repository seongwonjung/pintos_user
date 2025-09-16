#!/usr/bin/env bash
set -x # 디버그 모드를 활성화합니다. 실행되는 모든 명령어를 터미널에 출력합니다.

# Usage: select_test.sh [-q|-g] [-r]
#   -q|-g : 실행 모드 지정
#   -r    : clean & rebuild
if (( $# < 1 || $# > 2 )); then
  echo "Usage: $0 [-q|-g] [-r]"
  echo "   -q   : run tests quietly (no GDB stub)"
  echo "   -g   : attach via GDB stub (skip build)"
  echo "   -r   : force clean & full rebuild"
  exit 1
fi

MODE="$1"
if [[ "$MODE" != "-q" && "$MODE" != "-g" ]]; then
  echo "Usage: $0 [-q|-g] [-r]"
  exit 1
fi

# 두 번째 인자가 있으면 -r 체크
REBUILD=0
if (( $# == 2 )); then
  if [[ "$2" == "-r" ]]; then
    REBUILD=1
  else
    echo "Unknown option: $2"
    echo "Usage: $0 [-q|-g] [-r]"
    exit 1
  fi
fi

# 스크립트 자신이 있는 디렉터리 (src/threads/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 프로젝트 루트에서 Pintos 환경 활성화
source "${SCRIPT_DIR}/../activate"

# --------------------------------------------------
# .test_config 읽어서 tests 배열과 config_map 생성
# --------------------------------------------------
CONFIG_FILE="${SCRIPT_DIR}/.test_config"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Error: .test_config 파일이 없습니다: ${CONFIG_FILE}" >&2
  exit 1
fi

declare -A config_args   # 실행 인자
declare -A config_result # 결과 파일 경로
tests=()

while IFS=':' read -r test args result_dir; do
  [[ -z "${test// /}" || "${test// /}" == \#* ]] && continue
  test="$(echo "$test" | xargs)"
  args="$(echo "$args" | xargs)"
  result_dir="$(echo "$result_dir" | xargs)"
  
  # 변수 값이 깨졌는지 확인하기 위한 디버깅 출력
  echo "DEBUG: test='${test}', result_dir='${result_dir}'"
  
  config_result["$test"]="$result_dir"
  config_args["$test"]="$args"
  tests+=("$test")
done < "$CONFIG_FILE"

# 디버깅 모드를 비활성화합니다.
set +x

# 1) build/ 폴더가 없으면 무조건 처음 빌드
if [[ ! -d "${SCRIPT_DIR}/build" ]]; then
  echo "Build directory not found. Building Pintos threads..."
  make -C "${SCRIPT_DIR}" clean all
fi

# 2) -r 옵션이 있으면 clean & rebuild
if (( REBUILD )); then
  echo "Force rebuilding Pintos threads..."
  make -C "${SCRIPT_DIR}" clean all
fi

STATE_FILE="${SCRIPT_DIR}/.test_status"
declare -A status_map

if [[ -f "$STATE_FILE" ]]; then
  while read -r test stat; do
    status_map["$test"]="$stat"
  done < "$STATE_FILE"
fi

echo "=== Available Pintos Tests ==="
for i in "${!tests[@]}"; do
  idx=$((i+1))
  test="${tests[i]}"
  stat="${status_map[$test]:-untested}"
  case "$stat" in
    PASS) color="\e[32m" ;;
    FAIL) color="\e[31m" ;;
    *)    color="\e[0m"   ;;
  esac
  printf " ${color}%2d) %s\e[0m\n" "$idx" "$test"
done

read -p "Enter test numbers (e.g. '1 3 5' or '2-4'): " input
tokens=()
for tok in ${input//,/ }; do
  if [[ "$tok" =~ ^([0-9]+)-([0-9]+)$ ]]; then
    for ((n=${BASH_REMATCH[1]}; n<=${BASH_REMATCH[2]}; n++)); do
      tokens+=("$n")
    done
  else
    tokens+=("$tok")
  fi
done

declare -A seen=()
sel_tests=()
for n in "${tokens[@]}"; do
  if [[ "$n" =~ ^[0-9]+$ ]] && (( n>=1 && n<=${#tests[@]} )); then
    idx=$((n-1))
    if [[ -z "${seen[$idx]}" ]]; then
      sel_tests+=("${tests[idx]}")
      seen[$idx]=1
    fi
  else
    echo "Invalid test number: $n" >&2
    exit 1
  fi
done

echo "Selected tests: ${sel_tests[*]}"

passed=()
failed=()
{
  cd "${SCRIPT_DIR}/build" || exit 1

  count=0
  total=${#sel_tests[@]}
  for test in "${sel_tests[@]}"; do
    echo
    args_full="${config_args[$test]}"
    kernel_args="$(echo "${args_full%%--*}" | xargs)"
    run_args="$(echo "${args_full##*--}" | xargs)"
    dir="${config_result[$test]}"
    res="${dir}/${test}.result"
    
    mkdir -p ${dir}
    
    if [[ "$MODE" == "-q" ]]; then
      cmd="pintos ${kernel_args:+${kernel_args}} -- ${run_args} run ${test}"
      echo "Running ${test} in batch mode... "
      echo "\$ ${cmd}   # in batch mode"
      echo
      
      if make -s ${res} ARGS="${kernel_args:+${kernel_args}} -- ${run_args}"; then
        if grep -q '^PASS' ${res}; then
          echo "PASS"; passed+=("$test")
        else
          echo "FAIL"; failed+=("$test")
        fi
      else
        echo "FAIL"; failed+=("$test")
      fi
    else
      echo -e "=== Debugging \e[33m${test}\e[0m ($(( count + 1 ))/${total}) ==="
      echo -e "\e[33mVSCode의 \"Pintos Debug\" 디버그를 시작하세요.\e[0m"
      cmd="pintos --gdb ${kernel_args:+${kernel_args}} -- ${run_args} run ${test}"
      echo "\$ ${cmd}"
      eval "${cmd}" 2>&1 | tee "${dir}/${test}.output"
      repo_root="${SCRIPT_DIR}/.."
      ck="${repo_root}/${dir}/${test}.ck"
      if [[ -f "$ck" ]]; then
        perl -I "${repo_root}" "$ck" "${dir}/${test}" "${dir}/${test}.result"
        if grep -q '^PASS' "${dir}/${test}.result"; then
          echo "=> PASS"; passed+=("$test")
        else
          echo "=> FAIL"; failed+=("$test")
        fi
      else
        echo "=> No .ck script, skipping result."; failed+=("$test")
      fi
      echo "=== ${test} session end ==="
    fi

    ((count++))
    echo -e "\e[33mtest ${count}/${total} finish\e[0m"
  done
}

echo
echo "=== Test Summary ==="
echo "Passed: ${#passed[@]}"
for t in "${passed[@]}"; do echo "   - $t"; done
echo "Failed: ${#failed[@]}"
for t in "${failed[@]}"; do echo "   - $t"; done

for t in "${passed[@]}"; do
  status_map["$t"]="PASS"
done
for t in "${failed[@]}"; do
  status_map["$t"]="FAIL"
done

> "$STATE_FILE"
for test in "${!status_map[@]}"; do
  echo "$test ${status_map[$test]}"
done >| "$STATE_FILE"

