/// Base error for the OMEMO2 / PQXDH stack.
class Omemo2Exception implements Exception {
  const Omemo2Exception(this.message);
  final String message;
  @override
  String toString() => 'Omemo2Exception: $message';
}

class Omemo2KemException extends Omemo2Exception {
  const Omemo2KemException(super.message);
}

class Omemo2HandshakeException extends Omemo2Exception {
  const Omemo2HandshakeException(super.message);
}

class Omemo2InvalidMessageException extends Omemo2Exception {
  const Omemo2InvalidMessageException(super.message);
}

class Omemo2DuplicateMessageException extends Omemo2Exception {
  const Omemo2DuplicateMessageException(super.message);
}

class Omemo2NoSessionException extends Omemo2Exception {
  const Omemo2NoSessionException(super.message);
}
