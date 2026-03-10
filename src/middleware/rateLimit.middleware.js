/**
 * Simple rate limiter using Map
 * @param {Object} options
 * @param {number} options.windowMs - The window size in milliseconds
 * @param {number} options.max - Max number of requests within the window
 */
const requests = new Map();

export const rateLimiter = ({ windowMs = 60 * 1000, max = 5 } = {}) => {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();

    // Clean up old entries
    for (const [key, data] of requests.entries()) {
      if (now - data.timestamp > windowMs) {
        requests.delete(key);
      }
    }

    // Check current IP
    const currentRequests = requests.get(ip) || { count: 0, timestamp: now };

    if (now - currentRequests.timestamp > windowMs) {
      // Reset if window has passed
      currentRequests.count = 1;
      currentRequests.timestamp = now;
    } else if (currentRequests.count >= max) {
      // Too many requests
      return res.status(429).json({
        message: "Too many requests, please try again later.",
      });
    } else {
      // Increment request count
      currentRequests.count++;
    }

    requests.set(ip, currentRequests);
    next();
  };
};
