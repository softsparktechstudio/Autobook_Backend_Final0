import jwt from "jsonwebtoken";
import { pool } from "./db.js";

export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Authentication required." });
    const secret = process.env.JWT_SECRET;
    if (!secret || secret.length < 32) {
      return res.status(500).json({ error: "JWT_SECRET must be configured to at least 32 characters." });
    }
    const payload = jwt.verify(token, secret);
    const result = await pool.query(
      `SELECT u.id, u.full_name, u.email, u.status,
              m.organization_id, m.role
       FROM users u
       JOIN memberships m ON m.user_id = u.id
       WHERE u.id = $1 AND u.status = 'active'
       ORDER BY m.created_at LIMIT 1`,
      [payload.sub]
    );
    if (!result.rowCount) return res.status(401).json({ error: "User or organization membership is inactive." });
    req.user = result.rows[0];
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired session. Please sign in again." });
  }
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "You do not have permission to perform this action." });
    }
    next();
  };
}
