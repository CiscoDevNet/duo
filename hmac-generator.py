import base64, email.utils, hashlib, hmac, json, re, requests, urllib

# Fill in the values of hostname, secret_key and integration key using the
# values from the Duo protect an application page.
hostname='' # ex: 'api-0ad70c43.duosecurity.com'
secret_key='' # ex: 'nwR0hBAyosJCZHTvbkvoBuRAe581AtaTxmukwkH6'
integration_key='' # ex: 'DI2F0B2Z7P0ESU2D5PKV'

def sign(method, host, path, params, skey, ikey):
    """
    Return HTTP Basic Authentication ("Authorization" and "Date") headers.
    method, host, path: strings from request
    params: dict of request parameters
    skey: secret key
    ikey: integration key
    """

    # create canonical string
    now = email.utils.formatdate()
    canon = [now, method.upper(), host.lower(), path]
    args = []
    for key in sorted(params.keys()):
        val = params[key].encode("utf-8")
        args.append(
            '%s=%s' % (urllib.parse.
                       quote(key, '~'), urllib.parse.quote(val, '~')))
    canon.append('&'.join(args))
    canon = '\n'.join(canon)
    
    # sign canonical string
    sig = hmac.new(bytes(skey, encoding='utf-8'),
                   bytes(canon, encoding='utf-8'),
                   hashlib.sha1)
    
    # Print date, ASCII string, HMAC signature and Basic Authentication value
    print('')
    print(f'The Date for the header is: {now}')
    print(f'The ASCII string used for the HMAC signature:')
    print("______")
    print(f'{canon}')
    print("______")
    print(f'The generated HMAC Signature is: {sig.hexdigest()}')
    authorization = 'Basic %s' % base64.b64encode(bytes('%s:%s' % (ikey, sig.hexdigest()), encoding="utf-8")).decode()
    print(f'The Authorization for the header is: {authorization}')
    print('')

    # return headers
    return {'Date': now, 'Authorization': authorization}

# Get the information from the user
print("Input the information to generate the HMAC signature.")

# Prompt for integration key if it wasn't already provided
if len(integration_key) == 0:
    integration_key=input("Your Duo protected application integration key: ")

# Prompt for secret key if it wasn't already provided
if len(secret_key) == 0:
    secret_key=input("Your Duo protected application secret key: ")

# Prompt for hostname if it wasn't already provided
if len(hostname) == 0:
    hostname=input("Your Duo protected application API Hostname (ex: api-xxxxxxxx.duosecurity.com): ")

# Prompt for HTTP method and make the text upper case
http_method=input("The HTTP method of the API request (ex: GET, POST, PUT, DELETE): ")
http_method = http_method.upper()
if http_method != 'GET' and http_method != 'POST' and http_method != 'PUT' and http_method != 'DELETE':
    print(f'ERROR: The HTTP method {http_method} is unsupported.')
    exit()

# Prompt for the path of the API and add a / if it wasn't provided
path=input("The path of the API request (ex: /admin/v1/users): ")
if not path.startswith('/'):
    path = f'/{path}'

# Prompt for the parameters. Query params for GET and DELETE. Request body for everything else.
if http_method == 'GET' or http_method == 'DELETE':
    query_params = input("The query parameters of the API request. Press return/enter if there are no query parameters): ")
    
    params = dict(urllib.parse.parse_qsl(query_params))
else:
    print("Enter/Paste the request body in JSON format. When done or if there isn't a request body, press return/enter to add a newline, then use Ctrl-D (MacOS) or Ctrl-Z (Windows).")
    
    # Sample Format of the request body 
    # {
    #     "username": "myUsername",
    #     "firstname": "Jane",
    #     "lastname": "Doe"
    # }

    request_body = ''
    while True:
        try:
            request_body += input()
        except EOFError:
            break
    try:
        params = json.loads(request_body)
    except:
        print(f'ERROR: The request body is the right format')
        exit()
    query_params = ''

print('')

# Generate the HMAC signature.
headers = sign(http_method, hostname, path, params, secret_key, integration_key)

# See if the user wants to make the API request
make_request = input("Would you like to make the API request? (y/n) ")
if make_request.lower() == 'y':
    print('')

    print(f'The API request http method is: {http_method}')
    
    url = f'https://{hostname}{path}'
    if query_params != '':
        url += f'?{query_params}'
    print(f'The API request url is: {url}')

    print(f'The API request headers are: {headers}')
    print(f'The API request body is: {params}')

    if http_method == 'GET':
        response = requests.get(url=url, data=params, headers=headers)
    elif http_method == 'POST':
        response = requests.post(url=url, data=params, headers=headers)
    elif http_method == 'PUT':
        response = requests.put(url=url, data=params, headers=headers)
    elif http_method == 'DELETE':
        response = requests.put(url=url, data=params, headers=headers)
    
    if response == None:
        print('An error occurred while trying to make the API request.')
    else:
        print(f'HTTP Response status code: {response.status_code}')
        print(f'HTTP Response text: {response.text}')