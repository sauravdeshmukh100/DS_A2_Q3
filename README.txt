python bank_server.py HDFC 60051
source ~/grpc_env/bin/activate
deactivate
git push -u origin main
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. bank.proto


The method "utcnow" in class "datetime" is deprecated
  Use timezone-aware objects to represent datetimes in UTC; e.g. by calling .now(datetime.timezone.utc)Pylance
(method) def utcnow() -> datetime
Construct a UTC datetime from time.time().