const requireUser = async (req, res, next) => {
  try {
    const prefix = 'Bearer ';
    const auth = req.header('Authorization');

    if (!auth) {
      throw { name: 'AuthorizationError', message: 'The Authorization header is missing' };
    } else if (auth.startsWith(prefix)) {
      const token = auth.slice(prefix.length);

      try {
        const { id } = jwt.verify(token, JWT_SECRET);

        if (id) {
          req.user = await getUserById(id);
          next();
        } else {
          throw { name: 'AuthorizationError', message: 'Authorization token malformed' };
        }
      } catch ({ name, message }) {
        throw { name, message };
      }
    } else {
      throw { name: 'AuthorizationError', message: `Authorization token must start with ${prefix}` };
    }
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed', details: error.message });
  }
};

module.exports = {
  requireUser
};