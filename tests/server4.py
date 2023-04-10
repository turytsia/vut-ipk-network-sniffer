import socket

HOST = '172.25.3.177'
PORT = 2000  

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f'Server listening on port {PORT}...')

    while True:
        # Wait for a client to connect
        conn, addr = s.accept()
        print(f'Connected by {addr}')

        with conn:

            data = conn.recv(1024)
            print(f'Received: {data.decode()}')
            # Echo the data back to the client
            conn.sendall(data)
