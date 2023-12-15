# Using JSON Web Tokens

## Introduction

Use `Node.js`, `Express` and `Knex` to build an API with authentication and authorization using JSON Web Tokens.

## Instructions

### Task 1: Project Setup and Submission

Your assignment page on Canvas should contain instructions for submitting this project. If you are still unsure, reach out to School Staff.

<!--
// ------------------------------ DONE ABOVE THIS LINE ------------------------------ //
-->

### Task 2: Minimum Viable Product

You will complete the following tasks and do any extra wiring and package installation necessary for the app to compile and pass all tests.

#### 2A - Database Access Functions

Write the following user access functions inside `api/users/users-model.js`:

- [ ] `find`
- [ ] `findBy`
- [ ] `findById`

#### 2B - Middleware Functions

Write the following auth middlewares inside `api/auth/auth-middleware.js`:

- [ ] `restricted`
- [ ] `only`
- [ ] `checkUsernameExists`
- [ ] `validateRoleName`

#### 2C - Endpoints

Authentication will be implemented using JSON Web Tokens.

Write the following endpoints inside `api/auth/auth-router.js`:

- [ ] `[POST] /api/auth/register`
- [ ] `[POST] /api/auth/login`

The endpoints inside `api/users/users-router.js` are built already but check them out:

- [ ] `[GET] /api/users` - only users with a valid token can access
- [ ] `[GET] /api/users/:user_id` - only users with a valid token AND a role of 'admin' can access

#### 2D - Secrets File

Complete the `secrets/index.js` file.

#### Users Schema

| field    | data type        | metadata                                      |
| :------- | :--------------- | :-------------------------------------------- |
| user_id  | unsigned integer | primary key, auto-increments, generated by db |
| username | string           | required, unique                              |
| password | string           | required                                      |
| role_id  | unsigned integer | foreign key, required                         |

#### Roles Schema

| field     | data type        | metadata                                      |
| :-------- | :--------------- | :-------------------------------------------- |
| role_id   | unsigned integer | primary key, auto-increments, generated by db |
| role_name | string           | required, unique                              |

#### Notes

- Run tests locally executing `npm test`.
- The project comes with `migrate`, `rollback` and `seed` scripts in case you need to reset the database.
- You are welcome to create additional files but **do not move or rename existing files** or folders.
- Do not alter your `package.json` file except to install extra libraries or add extra scripts. Do not update existing libraries.
- In your solution, it is essential that you follow best practices and produce clean and professional results.
- Schedule time to review, refine, and assess your work.
- Perform basic professional polishing including spell-checking and grammar-checking on your work.

### Task 3: Stretch Goals

- Build a React application that implements components to register, login and view a list of users. Gotta keep sharpening your React skills.
<!--

# Tests

## Sanity check (6 ms)

    [x] [0] server.js

## [POST] /api/auth/login

    [ ] [1] responds with the correct message on valid credentials (753 ms)
    [ ] [2] responds with the correct status and message on invalid credentials (758 ms)
    [ ] [3] responds with a token with correct { subject, username, role_name, exp, iat } (763 ms)

## [POST] /api/auth/register

    [x] [4] creates a new user in the database when client does not provide role_name (760 ms)
    [x] [5] creates a new user with role_id 3 (the default role) when client does not provide role_name (762 ms)
    [x] [6] creates a new user with role_id 2 (existing role instructor) when client provides role_name instructor (762 ms)
    [x] [7] creates a new user with a brand new role_id when client provides a role_name that does not exist yet (761 ms)
    [x] [8] saves the user with a bcrypted password instead of plain text (761 ms)
    [ ] [9] responds with the correct user (when omitting role_name from the request) (768 ms)
    [x] [10] responds with the correct user (when choosing an existing role_name) (766 ms)
    [x] [11] responds with the correct user (when choosing a valid role_name not in db) (762 ms)
    [x] [12] leading and trailing whitespace is trimmed from the role_id (763 ms)
    [ ] [13] leading and trailing whitespace is trimmed from the role_id before validating (764 ms)
    [x] [14] responds with proper status and message on role_name over 32 chars after trimming (763 ms)
    [ ] [15] responds with proper status and message if a client tries to register as an admin (763 ms)
    [ ] [16] responds with proper status on success (763 ms)

## [GET] /api/users

    [ ] [17] requests without a token are bounced with proper status and message (761 ms)
    [ ] [18] requests with an invalid token are bounced with proper status and message (762 ms)
    [ ] [19] requests with a valid token obtain a list of users (761 ms)

## [GET] /api/users/:user_id

    [ ] [20] requests with a token with role_name admin obtain the user details (762 ms)
    [ ] [21] requests with a token with a role_name that is not admin are bounced with proper status and message (761 ms) -->
