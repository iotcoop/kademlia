class InvalidValueFormatException(Exception):

    def __init__(self, message):
        super(Exception, self).__init__(message)


class UnauthorizedOperationException(BaseException):

    def __init__(self):
        MESSAGE_PATTERN = 'You are not authorized to perform operation'

        BaseException.__init__(self, MESSAGE_PATTERN)


class InvalidSignException(BaseException):

    def __init__(self, message):
        MESSAGE_PATTERN = 'Signature is not valid: %s'

        BaseException.__init__(self, MESSAGE_PATTERN.format(str(message)))
