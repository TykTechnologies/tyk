from grpc.tools import protoc

protoc.main(
(
        '',
        '-I.',
        '--python_out=../bindings/python',
        '--grpc_python_out=../bindings/python',
        'coprocess_object.proto',
)
)
