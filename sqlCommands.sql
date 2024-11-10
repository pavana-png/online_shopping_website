// Database Connection
async function initializeDatabase() {
  db = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Chinnu@08",
    database: "ecommerce",
  });
  console.log("Database connected!");
}

const [productCount] = await db.query('SELECT COUNT(*) AS count FROM products');
const [orderCount] = await db.query('SELECT COUNT(*) AS count FROM orders');
const [userCount] = await db.query('SELECT COUNT(*) AS count FROM users');

const [products] = await db.query('SELECT * FROM products');

const [products] = await db.query('SELECT * FROM products');

await db.query(
          'INSERT INTO products (name, description, price, stock, image_url) VALUES (?, ?, ?, ?, ?)',
          [name, description, price, stock, image_url]
        );

await db.query(
          'UPDATE products SET name= ?, description=?, price=?, stock=?, image_url=? WHERE id = ?',
          [name, description, price, stock, image_url,id]
        );

const query = 'SELECT deleteProductById(?) AS result';

const query = 'SELECT * FROM Orders WHERE status = "Pending"';

const query = 'SELECT * FROM Orders WHERE DATE(order_date) = CURDATE()';

const query = 'SELECT * FROM Users WHERE DATE(join_date) = CURDATE()';

const query = `
      SELECT SUM(subquery.total_price) AS weekly_revenue
      FROM (
          SELECT OI.price * OI.quantity AS total_price
          FROM Orders O
          JOIN order_items OI ON O.id = OI.order_id
          WHERE YEAR(O.order_date) = YEAR(CURDATE()) 
          AND WEEK(O.order_date) = WEEK(CURDATE())
      ) AS subquery
  `;

const [products] = await db.query("SELECT * FROM products");

const [product] = await db.query('SELECT * FROM products WHERE id = ?', [productId]);

const [product] = await db.query('SELECT * FROM products WHERE id = ?', [productId]);

const cartInsertQuery = `
        INSERT INTO cart (user_id, product_id, quantity)
        VALUES (?, ?, 1)
        ON DUPLICATE KEY UPDATE quantity = quantity + 1;
      `;

const [existingUsers] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

const [result] = await db.query(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
      [name, email, hashedPassword, role || 'user'] // Default to 'user' if no role is provided
    );

const [result] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

const [cartItem] = await db.query(
          "SELECT * FROM cart WHERE user_id = ? AND product_id = ?",
          [userId, productId]
        );

await db.query(
            "UPDATE cart SET quantity = quantity + 1 WHERE user_id = ? AND product_id = ?",
            [userId, productId]
          );

await db.query(
            "INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)",
            [userId, productId]
          );

await db.query('DELETE FROM cart WHERE user_id = ? AND product_id = ?', [userId, productId]);

const [cartItems] = await db.query(
          `
      SELECT products.id, products.name, products.price, products.image_url, cart.quantity 
      FROM cart 
      JOIN products ON cart.product_id = products.id 
      WHERE cart.user_id = ?
    `,
          [userId]
        );

const [orders] = await db.query(`
              SELECT 
                  o.id AS order_id, 
                  o.delivery_date,
                  o.status,
                  oi.product_name, 
                  oi.quantity, 
                  oi.price,
                  oi.product_id, 
                  p.image_url  -- Fetch the image_url from products table
              FROM orders o
              JOIN order_items oi ON o.id = oi.order_id  -- Joining orders with order_items
              JOIN products p ON oi.product_id = p.id    -- Joining with products to get image_url
              WHERE o.user_id = ?
          `, [userId]);

const [userResult] = await db.query('SELECT name FROM users WHERE id = ?', [userId]);

const [orderResult] = await db.query(
      'INSERT INTO orders (user_id, user_name, address, phone, payment_method, order_date, delivery_date , status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [userId, userName, address, phone, paymentMethod, orderDate, deliveryDate, 'pending']
    );

const [cartItems] = await db.query('SELECT product_id, quantity FROM cart WHERE user_id = ?', [userId]);

const [productResult] = await db.query('SELECT name, price , image_url FROM products WHERE id = ?', [productId]);

await db.query(
        'INSERT INTO order_items (order_id, product_id, product_name, price, quantity) VALUES (?, ?, ?, ?, ?)',
        [ orderId, productId, productName, price, quantity]
      );

await db.query('DELETE FROM cart WHERE user_id = ?', [userId]);

const [result] = await db.query(
          'UPDATE orders SET status = ? WHERE id = ? AND user_id = ? AND status != "cancelled"',
          ['cancelled', orderId, userId]  // Ensuring the logged-in user is canceling their own order
      );

DELIMITER $$
CREATE FUNCTION deleteProductById(productId INT)
RETURNS VARCHAR(255)
DETERMINISTIC
MODIFIES SQL DATA
BEGIN
    DECLARE result VARCHAR(255);

    -- Delete product from the database
    DELETE FROM products WHERE id = productId;

    -- Return a success message
    SET result = 'Product deleted successfully!';
    
    RETURN result;
END;
DELIMITER ;

DELIMITER //
CREATE TRIGGER update_stock_after_order
AFTER INSERT ON order_items  -- Assuming you're inserting into order_items
FOR EACH ROW
BEGIN
    DECLARE product_id INT;

    -- Get the product ID from the newly inserted order_item
    SET product_id = NEW.product_id; -- Since product_id is directly available from order_items

    -- Update the stock level in the products table
    UPDATE products
    SET stock = stock - NEW.quantity  -- Ensure that quantity exists in order_items
    WHERE id = product_id;
END //
DELIMITER ;

DELIMITER //
CREATE TRIGGER before_insert_users
BEFORE INSERT ON users
FOR EACH ROW
BEGIN
    SET NEW.join_date = CURDATE();
END; //
DELIMITER ;