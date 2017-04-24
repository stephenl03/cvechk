# SECRET_KEY is used for session information and form input. 
# It should be set to something secure and random.
#
# SEVER_NAME should match the URL being handled by cvechk in order to allow
# for subdomain usage.
SECRET_KEY = 'changeme'
SERVER_NAME = 'example.com'

# REDISPASS is an optional password being used for the Redis instance.
REDISDB = 0
REDISHOST = '127.0.0.1'
REDISPORT = 6379
REDISPASS = ''
