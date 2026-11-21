#!/bin/zsh
cd "${0:A:h}"
if [[ ! -x .venv/bin/python ]]; then
  echo '请先在项目目录运行：python3 -m venv .venv'
  echo '然后运行：.venv/bin/python -m pip install -r requirements.txt'
  read 'reply?按回车退出'
  exit 1
fi
exec .venv/bin/python main.py "$@"
