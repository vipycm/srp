class Session {
  String key;
  String proof;

  Session({required this.key, required this.proof});
}

class Ephemeral {
  String public;
  String secret;

  Ephemeral({required this.public, required this.secret});
}
