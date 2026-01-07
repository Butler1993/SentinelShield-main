class RequestParser:
    """
    Parses Flask request objects into a normalized dictionary for inspection.
    """
    @staticmethod
    def parse(request):
        """
        Extracts relevant fields from the Flask request object.
        :param request: Flask request object
        :return: dict
        """
        # Normalize headers to a simple dict
        headers = {k: v for k, v in request.headers.items()}
        
        # Get body content safely
        body = ""
        try:
            if request.data:
                body = request.data.decode('utf-8', errors='ignore')
            elif request.form:
                body = str(request.form.to_dict())
        except Exception:
            body = "[Unreadable Body]"

        return {
            'timestamp': None, # To be added by logger or main loop
            'ip': request.remote_addr,
            'method': request.method,
            'path': request.path,
            'args': request.args.to_dict(),
            'headers': headers,
            'body': body,
            'full_url': request.url
        }
