import 'dart:math';
import 'package:convert/convert.dart';
import './bigint_ex.dart';
import './types.dart';
import './params.dart';

generateSalt() {
  final random = Random.secure();
  return hex.encode(List<int>.generate(Params.hashOutputBytes, (i) => random.nextInt(256)));
}

derivePrivateKey(String salt, String username, String password) {
  final H = Params.H;
  final s = BigInt.parse(salt, radix: 16);
  final x = H([
    s,
    H(['$username:$password'])
  ]);

  return x.toHex();
}

deriveVerifier(String privateKey) {
  final N = Params.N;
  final g = Params.g;
  return g.modPow(BigInt.parse(privateKey, radix: 16), N).toHex();
}

Ephemeral generateEphemeral() {
  final N = Params.N;
  final g = Params.g;
  final random = Random.secure();
  final randomHex = hex.encode(List<int>.generate(Params.hashOutputBytes, (i) => random.nextInt(256)));

  final a = BigInt.parse(randomHex, radix: 16);
  final A = g.modPow(a, N);

  return Ephemeral(secret: randomHex, public: A.toHex());
}

Session deriveSession(String clientSecretEphemeral, String serverPublicEphemeral, String salt, String username, String privateKey) {
  final N = Params.N;
  final g = Params.g;
  final k = Params.k;
  final H = Params.H;

  final a = BigInt.parse(clientSecretEphemeral, radix: 16);
  final B = BigInt.parse(serverPublicEphemeral, radix: 16);
  final s = BigInt.parse(salt, radix: 16);
  final I = username;
  final x = BigInt.parse(privateKey, radix: 16);

  final A = g.modPow(a, N);

  if (B % N == 0) {
    throw Exception('The server sent an invalid public ephemeral');
  }

  final u = H([A, B]);

  final S = (B - (k * (g.modPow(x, N)))).modPow(a + (u * x), N);

  final K = H([S]);

  final M = H([
    H([N]) ^ (H([g])),
    H([I]),
    s,
    A,
    B,
    K
  ]);

  return Session(key: K.toHex(), proof: M.toHex());
}

verifySession(String clientPublicEphemeral, Session clientSession, String serverSessionProof) {
  final H = Params.H;
  final A = BigInt.parse(clientPublicEphemeral, radix: 16);
  final M = BigInt.parse(clientSession.proof, radix: 16);
  final K = BigInt.parse(clientSession.key, radix: 16);

  final expected = H([A, M, K]);
  final actual = BigInt.parse(serverSessionProof, radix: 16);

  if (actual != expected) {
    throw Exception('Server provided session proof is invalid');
  }
}
