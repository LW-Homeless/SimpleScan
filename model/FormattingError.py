class FormattingError(Exception):

    def __init__(self, msg=None):

        if msg is None:
            msg = "Error de especificacion de puerto"

        super(FormattingError, self).__init__(msg)
