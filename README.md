#QuickCrypt


## Notes
This is a (possibly overly-complex) wrapper for Bcrypt in PHP. It was originally 
written to provide a seamless transition from old MD5 hashes to more secure 
hashes across multiple production servers that varied in capability as well as
easily update the work factor of Bcrypt hashes in the future. I got a little
fancy with it as a learning excercise, and I understand it could be much simpler.
Hopefully that hasn't broken anything.

I'm not a cryptography expert by any means, but I belive this to be a solid 
implementation of password hashing and validation functions. Some features, 
particularly the "key expansion" and the overly-complicated getRandomPassword() 
method were due to experimentation and curiousity rather than any sort of 
cryptographic necessity.

Since I had to go and break that one rule of crypto, it might turn out that some
code is not as clever as I thought, so if you notice something to be broken, 
feel free to let me know and/or submit a pull request.

**This has not been tested on all possible platforms!** It's worked on a handful
of different servers under different configurations, but be sure to test it to see
how it responds on **each server** you plan to use it on.

I think the code is fairly well-documented, so I'll let it speak for itself. These
brief examples should serve as a solid starting point for anyone wanting basic
password functions.

## Quick Examples

**Generate a random password**

```php
$qc = new QuickCrypt();
$random_password = $qc->getRandomPassword();
```

**Hash a plaintext password**

```php
$qc = new QuickCrypt();
$hash = $qc->hash($_POST['password']);
```

**Check a password against a hash**

```php
$qc = new QuickCrypt();
$success = $qc->checkPassword($_POST['password'], $hash_from_db);
```

**Automatically update a user's old password**

```php
$qc = new QuickCrypt();
if ($qc->checkPassword($_POST['password'], $hash)) {
       if ($qc->isOldHash($hash)) {
        $new_hash = $qc->hash($_POST['password']);
        $user->updatePassword($new_hash);
    }
}
```


