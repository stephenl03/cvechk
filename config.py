# SECRET_KEY is used for session information and form input. 
# It should be set to something secure and random.
#
# SEVER_NAME should match the URL being handled by cvechk in order to allow
# for subdomain usage.
SECRET_KEY = 'changeme'
SERVER_NAME = 'example.com:5000'

# REDISPASS is an optional password being used for the Redis instance.
REDIS_DB = 0
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_PASS = ''
