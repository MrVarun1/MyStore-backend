const { Router } = require("express");
const uuidV4 = require("uuid").v4;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const jwtSecret = process.env.SECRET;

const ROLES = {
  ADMIN: "admin",
  USER: "user",
  OWNER: "owner",
};

module.exports = function (db) {
  const router = Router();

  const authenticateUser = async (req, res, next) => {
    try {
      const token = req.headers["authorization"]?.split(" ")[1];
      if (!token) return res.status(401).json({ error: "Access Denied" });

      const verified = jwt.verify(token, jwtSecret);
      req.user = verified;
      next();
    } catch (err) {
      const message =
        err.name === "TokenExpiredError" ? "Token expired" : "Invalid Token";
      res.status(401).json({ error: message });
    }
  };

  const errorCatch = (err, req, res, next) => {
    console.log(`Error at ${req.path}:`, err);
    res.status(500).json({ error: err.message });
  };

  const roleMiddleware = (requiredRole) => {
    return function (req, res, next) {
      if (req.user.role !== requiredRole)
        return res
          .status(403)
          .json({ error: "Access forbidden for this role" });
      next();
    };
  };

  router.post("/signup", async (req, res, next) => {
    try {
      const { name, email, password, address } = req.body;

      const isExistQuery = `
          SELECT *
          FROM users
          WHERE email = ?
          `;

      const existingUser = await db.get(isExistQuery, [email]);

      if (existingUser)
        return res.status(400).json({ error: "Email already registered" });

      if (password.length < 8 || password.length > 16)
        return res
          .status(400)
          .json({ error: "Password Length should be between 8 and 16" });

      const hashedPassword = await bcrypt.hash(password, 8);

      const registerUserQuery = `
      INSERT INTO users (user_id, name, email, password, address, role)
      VALUES 
          (?,?,?,?,?,'user')`;

      await db.run(registerUserQuery, [
        uuidV4(),
        name,
        email,
        hashedPassword,
        address,
      ]);

      const user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);

      const token = jwt.sign(
        {
          email: user.email,
          user_id: user.user_id,
          name: user.name,
          role: user.role,
        },
        jwtSecret,
        {
          expiresIn: "1 day",
        }
      );

      res.json({
        message: "User registered and logged in successfully",
        token,
        role: user.role,
      });
    } catch (err) {
      next(err);
    }
  });

  router.post("/login", async (req, res, next) => {
    try {
      const { email, password } = req.body;

      const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);

      if (!user)
        return res.status(400).json({ error: "Invalid email or password" });

      const isValid = await bcrypt.compare(password, user.password);

      if (!isValid)
        return res.status(400).json({ error: "Invalid email or password" });

      const token = jwt.sign(
        {
          email: user.email,
          user_id: user.user_id,
          name: user.name,
          role: user.role,
        },
        jwtSecret,
        {
          expiresIn: "1 day",
        }
      );

      res.json({ message: "Login successfully", token, role: user.role });
    } catch (err) {
      next(err);
    }
  });

  router.get("/validateJWT", authenticateUser, async (req, res) => {
    const { user_id, role } = req.user;
    res.json({ message: "Valid JWT", user: { user_id, role } });
  });

  router.put("/change-password", authenticateUser, async (req, res, next) => {
    try {
      const { user_id } = req.user;
      const { old_password, new_password } = req.body;

      const user = await db.get(`SELECT * FROM users WHERE user_id = ?`, [
        user_id,
      ]);

      const isValid = await bcrypt.compare(old_password, user.password);
      if (!isValid)
        return res.status(400).json({ error: "Invalid old password" });

      const hashedPassword = await bcrypt.hash(new_password, 8);

      await db.run(
        `
        UPDATE users
        SET password = ?
        WHERE user_id = ?
        `,
        [hashedPassword, user_id]
      );

      res.json({ message: "Password changed successfully" });
    } catch (err) {
      next(err);
    }
  });

  router.get(
    "/admin/totals",
    authenticateUser,
    roleMiddleware(ROLES.ADMIN),
    async (req, res, next) => {
      try {
        const total_users_row = await db.get(
          `SELECT COUNT(user_id) AS count FROM users`
        );
        const total_stores_row = await db.get(
          `SELECT COUNT(store_id) AS count FROM stores`
        );
        const total_ratings_row = await db.get(
          `SELECT COUNT(rating_id) AS count FROM ratings`
        );

        const totals = {
          total_users: total_users_row.count,
          total_stores: total_stores_row.count,
          total_ratings: total_ratings_row.count,
        };

        return res.json({ totals });
      } catch (err) {
        next(err);
      }
    }
  );

  router.post(
    "/admin/users",
    authenticateUser,
    roleMiddleware(ROLES.ADMIN),
    async (req, res, next) => {
      try {
        const { name, email, password, address, role } = req.body;

        const isExistQuery = `
              SELECT *
              FROM users
              WHERE email = ?
              `;

        const existingUser = await db.get(isExistQuery, [email]);

        if (existingUser)
          return res.status(400).json({ error: "Email already registered" });

        const hashedPassword = await bcrypt.hash(password, 8);

        const registerUserQuery = `
          INSERT INTO users (user_id, name, email, password, address, role)
          VALUES 
              (?,?,?,?,?,?)`;

        await db.run(registerUserQuery, [
          uuidV4(),
          name,
          email,
          hashedPassword,
          address,
          role,
        ]);

        res.json({ message: "User registered successfully" });
      } catch (err) {
        next(err);
      }
    }
  );

  router.post(
    "/admin/store",
    authenticateUser,
    roleMiddleware(ROLES.ADMIN),
    async (req, res, next) => {
      try {
        const { store_name, email, address, owner_user_id } = req.body;

        await db.run(
          `
            INSERT INTO stores (store_id, store_name, email, address, owner_user_id)
            VALUES 
                (?,?,?,?,?)`,
          [uuidV4(), store_name, email, address, owner_user_id]
        );

        res.json({ message: "Store registered successfully" });
      } catch (err) {
        next(err);
      }
    }
  );

  router.get(
    "/admin/stores",
    authenticateUser,
    roleMiddleware(ROLES.ADMIN),
    async (req, res, next) => {
      try {
        const { search = "", sort = "store_name" } = req.query;

        const allowedSortFields = ["store_name", "email", "rating"];
        if (!allowedSortFields.includes(sort))
          return res.status(400).json({ error: "Invalid sort field" });

        const get_stores_query = `
        SELECT 
        s.store_id AS store_id,
        s.store_name AS store_name,
        s.email AS email,
        s.address AS address,
        ROUND(AVG(r.rating), 2) AS rating
        FROM stores s 
        LEFT JOIN ratings r ON s.store_id = r.store_id
        WHERE s.store_name LIKE ? 
        OR s.address LIKE ?
        GROUP BY s.store_id
        ORDER BY ${sort}
    `;

        const stores = await db.all(get_stores_query, [
          `%${search}%`,
          `%${search}%`,
        ]);

        res.json({ stores });
      } catch (err) {
        next(err);
      }
    }
  );

  router.get(
    "/admin/users",
    authenticateUser,
    roleMiddleware(ROLES.ADMIN),
    async (req, res, next) => {
      try {
        const { search = "", sort = "name" } = req.query;

        const allowedSortFields = ["name", "email", "role", "rating"];
        if (!allowedSortFields.includes(sort))
          return res.status(400).json({ error: "Invalid sort field" });

        const get_users_query = `
      SELECT 
        u.user_id AS user_id,
        u.name AS name,
        u.email AS email,
        u.address AS address,
        u.role AS role, 
        ROUND(AVG(r.rating), 2) AS rating
      FROM users u 
        LEFT JOIN stores s ON u.user_id = s.owner_user_id
        LEFT JOIN ratings r ON s.store_id = r.store_id
      WHERE u.name LIKE ?
        OR u.email LIKE ?
        OR u.role LIKE ?
      GROUP BY u.user_id
      ORDER BY ${sort}
      `;

        const users = await db.all(get_users_query, [
          `%${search}%`,
          `%${search}%`,
          `%${search}%`,
        ]);

        res.json({ users });
      } catch (err) {
        next(err);
      }
    }
  );

  router.get(
    "/user/stores",
    authenticateUser,
    roleMiddleware(ROLES.USER),
    async (req, res, next) => {
      try {
        const { user_id } = req.user;
        const { search = "", sort = "store_name" } = req.query;

        const allowedSortFields = ["store_name", "email", "rating"];
        if (!allowedSortFields.includes(sort))
          return res.status(400).json({ error: "Invalid sort field" });

        const get_stores_query = `
        SELECT 
            s.store_id,
            s.store_name,
            s.address,
        ROUND(AVG(r.rating), 2) AS rating,
            ur.rating AS user_rating
        FROM stores s
            LEFT JOIN ratings r ON s.store_id = r.store_id
            LEFT JOIN ratings ur ON s.store_id = ur.store_id AND ur.user_id = ?
        WHERE s.store_name LIKE ? OR s.address LIKE ?
        GROUP BY s.store_id
        ORDER BY ${sort}
      `;

        const stores = await db.all(get_stores_query, [
          user_id,
          `%${search}%`,
          `%${search}%`,
        ]);

        res.json({ stores });
      } catch (err) {
        next(err);
      }
    }
  );

  router.post(
    "/rating/:store_id",
    authenticateUser,
    roleMiddleware(ROLES.USER),
    async (req, res, next) => {
      try {
        const { rating } = req.body;
        const { store_id } = req.params;
        const { user_id } = req.user;

        const existingRating = await db.get(
          `SELECT * FROM ratings WHERE store_id = ? AND user_id = ?`,
          [store_id, user_id]
        );

        if (existingRating) {
          return res
            .status(400)
            .json({ error: "You have already rated this store" });
        }

        await db.run(
          `INSERT INTO ratings (rating_id, user_id, store_id, rating)
        VALUES (?,?,?,?)`,
          [uuidV4(), user_id, store_id, rating]
        );

        res.json({ message: "Rating posted successfully" });
      } catch (err) {
        next(err);
      }
    }
  );

  router.put(
    "/rating/:store_id",
    authenticateUser,
    roleMiddleware(ROLES.USER),
    async (req, res, next) => {
      try {
        const { store_id } = req.params;
        const { rating } = req.body;
        const { user_id } = req.user;

        const ratingRow = await db.get(
          `SELECT * FROM ratings WHERE store_id = ? AND user_id = ?`,
          [store_id, user_id]
        );
        if (!ratingRow)
          return res.status(400).json({ error: "Rating not found to update" });

        await db.run(
          `
            UPDATE ratings 
            SET rating = ?
            WHERE store_id = ? AND user_id = ?
            `,
          [rating, store_id, user_id]
        );

        res.json({ message: "Rating updated successfully" });
      } catch (err) {
        next(err);
      }
    }
  );

  router.get(
    "/store/users",
    authenticateUser,
    roleMiddleware(ROLES.OWNER),
    async (req, res, next) => {
      try {
        const { user_id } = req.user;
        const { search = "", sort = "name" } = req.query;

        const allowedSortFields = ["name", "rating"];
        if (!allowedSortFields.includes(sort))
          return res.status(400).json({ error: "Invalid sort field" });

        const get_users_ratings_query = `
        SELECT 
            ur.user_id AS user_id,
            ur.name AS name,
            r.rating AS rating
        FROM users u
        LEFT JOIN stores s ON u.user_id = s.owner_user_id
        LEFT JOIN ratings r ON s.store_id = r.store_id
        LEFT JOIN users ur ON r.user_id = ur.user_id
        WHERE u.user_id = ?
        AND ur.name LIKE ?
        ORDER BY ${sort}`;

        const users_ratings = await db.all(get_users_ratings_query, [
          user_id,
          `%${search}%`,
        ]);

        const get_store_details = `
        SELECT 
          s.store_name AS store_name,
          s.store_id AS store_id,
          ROUND(AVG(r.rating), 2) AS rating,
          s.owner_user_id AS owner_user_id
        FROM stores s 
        LEFT JOIN ratings r ON s.store_id = r.store_id
        WHERE s.owner_user_id =?
        GROUP BY s.store_id
        `;

        const store_details = await db.get(get_store_details, [user_id]);

        res.json({ store_details, users_ratings });
      } catch (err) {
        next(err);
      }
    }
  );

  router.use(errorCatch);

  return router;
};
