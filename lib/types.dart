class Session {
  String key;
  String proof;

  Session({this.key, this.proof});
}

class Ephemeral {
  String public;
  String secret;

  Ephemeral({this.public, this.secret});
}
