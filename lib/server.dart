import 'dart:math';
import 'package:convert/convert.dart';
import './bigint_ex.dart';
import './types.dart';
import './params.dart';

Ephemeral generateEphemeral(String verifier) {
  final N = Params.N;
  final g = Params.g;
  final k = Params.k;

  final v = BigInt.parse(verifier, radix: 16);

  final random = Random.secure();
  final randomHex = hex.encode(List<int>.generate(Params.hashOutputBytes, (i) => random.nextInt(256)));

  final b = BigInt.parse(randomHex, radix: 16);
  final B = (k * v + g.modPow(b, N)) % N;

  return Ephemeral(secret: randomHex, public: B.toHex());
}

Session deriveSession(String serverSecretEphemeral, String clientPublicEphemeral, String salt, String username, String verifier, String clientSessionProof) {
  final N = Params.N;
  final g = Params.g;
  final k = Params.k;
  final H = Params.H;

  final b = BigInt.parse(serverSecretEphemeral, radix: 16);
  final A = BigInt.parse(clientPublicEphemeral, radix: 16);
  final s = BigInt.parse(salt, radix: 16);
  final I = username;
  final v = BigInt.parse(verifier, radix: 16);

  final B = (k * v + g.modPow(b, N)) % N;

  if (A % N == 0) {
    throw Exception('the client sent an invalid public ephemeral');
  }

  final u = H([A, B]);

  final S = (A * (v.modPow(u, N))).modPow(b, N);

  final K = H([S]);

  final M = H([
    H([N]) ^ (H([g])),
    H([I]),
    s,
    A,
    B,
    K
  ]);

  final expected = M;
  final actual = BigInt.parse(clientSessionProof, radix: 16);

  if (actual != expected) {
    throw Exception('Client provided session proof is invalid');
  }

  final P = H([A, M, K]);

  return Session(key: K.toHex(), proof: P.toHex());
}
