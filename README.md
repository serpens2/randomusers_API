Basic CRUD API to interact with SQL-database containing users info. 

API is made via FastAPI, and connection to PostgreSQL is done via psycopg2. Some endpoints retreive data from [remote API](https://randomuser.me/).

Project includes authorization mechanism via JWT-tokens. Private and public keys are in .env file. Of course, in real projects
you **_never_ publish private key**.

We've also included Dockerfile and docker-compose.yml in the repo. We've tested deploy and it seems to work fine.

**Note:** to run `main.py` outside docker container, change `DB_HOST` to 'localhost' (or any other host you use) in .env file.

## List of endpoints
- `/generate_users/{num}`: returns `num` random users from [remote API](https://randomuser.me/).
- `/read_users`: returns all users from database (if it exists), limited by query parameter `limit_by`.
- `/add_users/{num}`: retreives `num` users via `/generate_users/{num}` and inserts them into database. Also initializes database if it didn't exist.
- `/registrate_user`: adds user in database with data from the form.
- `/login`: issues JWT-token of 'Bearer' type. Token lasts for 15 minutes (see .env).
- `/delete/{username}`: deletes user. This endpoint requires you to login as admin (username = password = 'admin').
- `/me`: uses JWT-token to return info about current user.
