import 'package:srp/client.dart' as client;
import 'package:srp/server.dart' as server;
import 'package:test/test.dart';

void main() {
  test('srp test', () {
    final username = 'x@vipycm.com';
    final password = 'password';

    final salt = client.generateSalt();
    final privateKey = client.derivePrivateKey(salt, username, password);
    final verifier = client.deriveVerifier(privateKey);

    final clientEphemeral = client.generateEphemeral();
    final serverEphemeral = server.generateEphemeral(verifier);

    final clientSession = client.deriveSession(clientEphemeral.secret, serverEphemeral.public, salt, username, privateKey);
    final serverSession = server.deriveSession(serverEphemeral.secret, clientEphemeral.public, salt, username, verifier, clientSession.proof);

    client.verifySession(clientEphemeral.public, clientSession, serverSession.proof);

    expect(clientSession.key, serverSession.key);
  });
}
