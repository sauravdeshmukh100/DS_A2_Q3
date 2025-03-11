python bank_server.py HDFC 60051
source ~/grpc_env/bin/activate
git push -u origin main
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. bank.proto
