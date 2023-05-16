import coprocess_object_pb2, coprocess_object_pb2_grpc
from coprocess_session_state_pb2 import SessionState

import grpc, time, json, gzip

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

from concurrent import futures

def MyPreMiddleware(coprocess_object):
  coprocess_object.request.set_headers["MyPreMiddleware"] = "MyPreMiddleware"
  return coprocess_object

def MyPostMiddleware(coprocess_object):
  coprocess_object.response.headers["MyPostMiddleware"] = "MyPostMiddleware"
  return coprocess_object

def MyResponseMiddleware(coprocess_object):
    # Unzip Response
    gzip_decoded_body = gzip.decompress(coprocess_object.response.raw_body)
    json_body = json.loads(str(gzip_decoded_body, 'utf-8'))
    ids = list()

    # Extract IDs
    for item in json_body:
        ids.append(item['id'])

    # Format Response
    coprocess_object.response.body = json.dumps(ids)
    coprocess_object.response.raw_body = json.dumps(ids).encode('utf-8')
    coprocess_object.response.headers['Content-Length'] = str(len(coprocess_object.response.raw_body))
    coprocess_object.response.headers['Content-Encoding'] = ''
    return coprocess_object

def MyAuthCheck(coprocess_object):
  valid_token = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
  request_token = coprocess_object.request.headers["Authorization"]

  if request_token == valid_token:
      new_session = SessionState()
      new_session.rate = 1000.0
      new_session.per = 1.0
      coprocess_object.metadata["token"] = "mytoken"
      coprocess_object.session.CopyFrom(new_session)

  else:
      coprocess_object.request.return_overrides.response_code = 401
      coprocess_object.request.return_overrides.response_error = 'Not authorized (Python middleware)'

  return coprocess_object

class MyDispatcher(coprocess_object_pb2_grpc.DispatcherServicer):
  def Dispatch(self, coprocess_object, context):
    if coprocess_object.hook_name == "MyPreMiddleware":
        coprocess_object = MyPreMiddleware(coprocess_object)

    if coprocess_object.hook_name == "MyPostMiddleware":
        coprocess_object = MyPostMiddleware(coprocess_object)

    if coprocess_object.hook_name == "MyAuthCheck":
        coprocess_object = MyAuthCheck(coprocess_object)

    if coprocess_object.hook_name == "MyResponseMiddleware":
        coprocess_object = MyResponseMiddleware(coprocess_object)

    return coprocess_object

  def DispatchEvent(self, event_wrapper, context):
    event = json.loads(event_wrapper.payload)
    return coprocess_object_pb2_grpc.EventReply()


def serve():
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
  coprocess_object_pb2_grpc.add_DispatcherServicer_to_server(
      MyDispatcher(), server)
  server.add_insecure_port('[::]:5555')
  server.start()
  try:
    while True:
      time.sleep(_ONE_DAY_IN_SECONDS)
  except KeyboardInterrupt:
    server.stop(0)

if __name__ == '__main__':
  serve()