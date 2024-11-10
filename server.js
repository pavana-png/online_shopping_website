const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const router = express.Router();
const moment = require('moment'); // Make sure to install this using `npm install moment`
//const db = require('./db');

const app = express();
let db; // Declare db here to make it accessible

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
// for parsing application/json
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: true,
  })
);

// Set EJS as the templating engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "templates"));
app.use(express.static('public')); // 'public' is the folder where your images are stored


// Middleware to check if user is logged in
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  } else {
    res.redirect("/login"); // Redirect to login if not authenticated
  }
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') {
    return next();
  } else {
    res.status(403).send('Access Denied. Admins Only');
  }
}




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

initializeDatabase()
  .then(() => {
    // Render the home page
    app.get("/", (req, res) => {
      res.render("index");
    });

    app.get("/index", (req, res) => {
      res.render("index"); // Ensure you have an index.ejs file in the views folder
    });

    app.get("/login", (req, res) => {
      res.render("index"); // This assumes the login form is on the home page (index.ejs)
    });

    app.get('/help', (req, res) => {
      const userLoggedIn = req.session.user ? true : false; // Assuming session management for user
      const message = " ";
      res.render('help', { message , userLoggedIn });
  });
  

    app.get("/logout", (req, res) => {
      console.log("Logout route hit"); // Debugging message
      req.session.destroy((err) => {
        if (err) {
          console.error("Error during logout:", err);
          return res.status(500).send("Error logging out");
        }
        res.redirect("/index"); // Redirect to the homepage after logout
      });
    });

    app.get('/admin/dashboard', isAuthenticated, isAdmin, async (req, res) => {
      try {
        // Fetch total counts for products, users, and orders
        const [productCount] = await db.query('SELECT COUNT(*) AS count FROM products');
        const [orderCount] = await db.query('SELECT COUNT(*) AS count FROM orders');
        const [userCount] = await db.query('SELECT COUNT(*) AS count FROM users');
        const user = req.session.user;
        res.render('admin/dashboard', {user,
          productCount: productCount[0].count,
          orderCount: orderCount[0].count,
          userCount: userCount[0].count
        });
      } catch (error) {
        console.error('Error fetching admin dashboard data:', error);
        res.status(500).send('Server error');
      }
    });

    app.get('/admin/addProduct', isAuthenticated, isAdmin, async (req, res) => {
      try {
        // Fetch products from the database
        const [products] = await db.query('SELECT * FROM products');
        const user = req.session.user;
        // Render the view and pass the fetched products
        res.render('admin/addProduct', { products, user });
      } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).send('Server error');
      }
    });

    app.get('/admin/products/add', isAuthenticated, isAdmin, async (req, res) => {
      try {
        // Fetch products from the database
        const [products] = await db.query('SELECT * FROM products');
        const user = req.session.user;
        // Render the view and pass the fetched products
        res.render('admin/addProduct', { products, user });
      } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).send('Server error');
      }
    });
    
    
    app.post('/admin/products/add', isAuthenticated, isAdmin, async (req, res) => {
      const { name, description, price, stock, image_url } = req.body;
      try {
        await db.query(
          'INSERT INTO products (name, description, price, stock, image_url) VALUES (?, ?, ?, ?, ?)',
          [name, description, price, stock, image_url]
        );
        res.redirect('/admin/products/add');
      } catch (error) {
        console.error('Error adding product:', error);
        res.status(500).send('Server error');
      }
    });

    app.post('/admin/products/update', isAuthenticated, isAdmin, async (req, res) => {
      const { name, description, price, stock, image_url,id } = req.body;
      try {
        await db.query(
          'UPDATE products SET name= ?, description=?, price=?, stock=?, image_url=? WHERE id = ?',
          [name, description, price, stock, image_url,id]
        );
        res.redirect('/admin/products/add');
      } catch (error) {
        console.error('Error adding product:', error);
        res.status(500).send('Server error');
      }
    });

    

    app.post('/admin/products/delete', (req, res) => {
      const productId = req.body.id;
      console.log('Product ID to delete:', productId); // Log the received ID
  
      const query = 'SELECT deleteProductById(?) AS result'; // Call the MySQL function
  
      db.query(query, [productId], (err, results) => {
          if (err) {
              console.error('Error executing MySQL query:', err);
              return res.status(500).send({ message: 'Error deleting product: ' + err.message });
          }
  
          const resultMessage = results[0].result;
          console.log(resultMessage); // Log the result for debugging
  
          
          res.redirect('/admin/products/add'); // Redirect to the products page after deletion
 // Send the result back to the client
      });
  });

    
    app.get("/admin/dashboard",isAuthenticated, isAdmin, (req, res) => {
      const user = req.session.user;
      res.render("admin/dashboard",{user});
    });

   // Route to retrieve pending orders (Simple Query)
app.get('/admin/pending-orders', async (req, res) => {
  const query = 'SELECT * FROM Orders WHERE status = "Pending"';
  try {
      const [results] = await db.query(query);
      res.json(results);
  } catch (err) {
      console.error('Error fetching pending orders:', err);
      res.status(500).json({ error: 'Internal server error' });
  }
});

// Route to retrieve orders placed today (Simple Query)
app.get('/admin/orders-today', async (req, res) => {
  const query = 'SELECT * FROM Orders WHERE DATE(order_date) = CURDATE()';
  try {
      const [results] = await db.query(query);
      res.json(results);
  } catch (err) {
      console.error('Error fetching orders placed today:', err);
      res.status(500).json({ error: 'Internal server error' });
  }
});

// Route to retrieve new users added today (Simple Query)
app.get('/admin/new-users-today', async (req, res) => {
  const query = 'SELECT * FROM Users WHERE DATE(join_date) = CURDATE()';
  try {
      const [results] = await db.query(query);
      res.json(results);
  } catch (err) {
      console.error('Error fetching new users:', err);
      res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/admin/revenue-today', async (req, res) => {
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

  try {
      const [results] = await db.query(query);
      console.log(results); // Log the results to check their structure
      
      if (results.length > 0 && results[0].weekly_revenue !== null) {
          res.json(results[0]);
      } else {
          res.json({ weekly_revenue: 0 }); // Set to 0 if no revenue found
      }
  } catch (err) {
      console.error('Error fetching weekly revenue:', err);
      res.status(500).json({ error: 'Internal server error' });
  }
});

app.get("/about", (req,res)=>{
  res.render("about", {user : req.session.user});
});

    // Render the products page
    app.get("/products", async (req, res) => {
      try {
        const [products] = await db.query("SELECT * FROM products");
        const user = req.session.user ? req.session.user.name : null;

        res.render("products", { products, user });
      } catch (err) {
        console.error("Error fetching products:", err);
        res.status(500).send("Internal Server Error");
      }
    });

    app.get("/order-confirmation",(req,res)=>{
      res.render("order-confirmation", {user : req.session.user})
    });

    app.get("/payment", (req, res) => {
      // Check if the user is logged in
      if (req.session.user) {
        // Render the payment page, passing the user object to the EJS template
        res.render("payment", { user: req.session.user });
      } else {
        // If the user is not logged in, redirect them to the login page
        res.redirect("/login");
      }
    });

    app.get('/product/:id', async (req, res) => {
      try {
          const productId = req.params.id;  // Get the product ID from the URL
          const [product] = await db.query('SELECT * FROM products WHERE id = ?', [productId]);  // Fetch product details
          
          if (!product || product.length === 0) {
              return res.status(404).send('Product not found');
          }
          
          // Pass both product details and the req object to the EJS template
          res.render('detailed', { 
              product: product[0], 
              req: req  // Pass the req object to the template
          });
      } catch (error) {
          console.error('Error fetching product details:', error);
          res.status(500).send('Server error');
      }
  });
  
  
   // Add-to-cart route
app.post('/add-to-cart/:id', isAuthenticated, async (req, res) => {
  const productId = req.params.id;
  const userId = req.session.user.id; // Ensure you are getting the correct user ID from the session

  try {
    // Query the product details from the database
    const [product] = await db.query('SELECT * FROM products WHERE id = ?', [productId]);

    // If the product exists, add it to the cart
    if (product.length > 0) {
      // Insert product into the cart or update the quantity if it already exists in the user's cart
      const cartInsertQuery = `
        INSERT INTO cart (user_id, product_id, quantity)
        VALUES (?, ?, 1)
        ON DUPLICATE KEY UPDATE quantity = quantity + 1;
      `;
      await db.query(cartInsertQuery, [userId, productId]);

      // Redirect to the cart page after adding the product
      res.redirect('/cart');
    } else {
      // Handle the case where the product does not exist
      res.status(404).send('Product not found');
    }
  } catch (error) {
    console.error('Error adding product to cart:', error);
    res.status(500).send('Server error');
  }
});

// Register a new user (or admin) and insert into 'users' table
app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body; // Accept role from form (optional)
  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if user already exists
    const [existingUsers] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    if (existingUsers.length > 0) {
      return res.status(400).send("User already exists!");
    }

    // Insert new user into the database
    const [result] = await db.query(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
      [name, email, hashedPassword, role || 'user'] // Default to 'user' if no role is provided
    );

    // Get the user ID after insertion (result.insertId gives the new user ID)
    const userId = result.insertId;

    // Store user info in session after registration
    req.session.user = { id: userId, name, role: role || 'user' }; // Store role in session

    if (role === 'admin') {
      res.redirect("/admin/dashboard"); // Redirect to admin dashboard if admin
    } else {
      res.redirect("/products"); // Redirect to products after successful registration for users
    }
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Login user (or admin)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [result] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

    if (result.length === 0) {
      return res.status(404).send("User not found!");
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      // Store user details in session
      req.session.user = { id: user.id, name: user.name, role: user.role };

      if (user.role === 'admin') {
        res.redirect("/admin/dashboard"); // Redirect admin to admin dashboard
      } else {
        res.redirect("/products"); // Redirect regular user to products page
      }
    } else {
      res.status(401).send("Incorrect password!");
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).send("Internal Server Error");
  }
});


    let cart = [];

    // Add to cart route
    app.post("/cart/add", async (req, res) => {
      const { productId } = req.body;

      // Ensure the user is logged in
      if (!req.session.user) {
        return res.redirect("/login");
      }

      const userId = req.session.user.id; // Get the logged-in user's ID

      try {
        // Check if the product is already in the user's cart
        const [cartItem] = await db.query(
          "SELECT * FROM cart WHERE user_id = ? AND product_id = ?",
          [userId, productId]
        );

        if (cartItem.length > 0) {
          // If the product is already in the cart, update the quantity
          await db.query(
            "UPDATE cart SET quantity = quantity + 1 WHERE user_id = ? AND product_id = ?",
            [userId, productId]
          );
        } else {
          // Otherwise, insert a new entry in the cart table
          await db.query(
            "INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)",
            [userId, productId]
          );
        }

        res.redirect("/cart");
      } catch (err) {
        console.error("Error adding to cart:", err);
        res.status(500).send("Internal Server Error");
      }
    });

    // Remove item from cart route
app.post('/cart/remove', async (req, res) => {
  const { productId } = req.body;

  // Ensure the user is logged in
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id; // Get the logged-in user's ID

  try {
    // Remove the item from the cart
    await db.query('DELETE FROM cart WHERE user_id = ? AND product_id = ?', [userId, productId]);

    res.redirect('/cart'); // Redirect to the cart page after removing
  } catch (err) {
    console.error('Error removing item from cart:', err);
    res.status(500).send('Internal Server Error');
  }
});

    // Display cart items for the logged-in user
    app.get("/cart", isAuthenticated, async (req, res) => {
      const userId = req.session.user.id; // Get the logged-in user's ID
      const userName = req.session.user.name;
      try {
        // Fetch products in the cart for the logged-in user
        const [cartItems] = await db.query(
          `
      SELECT products.id, products.name, products.price, products.image_url, cart.quantity 
      FROM cart 
      JOIN products ON cart.product_id = products.id 
      WHERE cart.user_id = ?
    `,
          [userId]
        );

        // Calculate total price
        const cartTotal = cartItems.reduce(
          (total, item) => total + item.price * item.quantity,
          0
        );

        res.render("cart", { cartItems, cartTotal, userName });
      } catch (err) {
        console.error("Error fetching cart items:", err);
        res.status(500).send("Internal Server Error");
      }
    });
    
    app.get('/orders', isAuthenticated, async (req, res) => {
      try {
          // Fetch the user ID from the session
          const userId = req.session.user.id;
  
          // Fetch complete order details from the database including product image
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

          console.log(orders.status);
  
          // Pass the order details to the orders.ejs view, including product images
          res.render('orders', { orders });
      } catch (error) {
          console.error('Error fetching orders:', error);
          res.status(500).send('Server error');
      }
  });
  
 

app.post('/place-order', async (req, res) => {
  try {
    // Ensure the user is authenticated by checking req.session.user
    if (!req.session.user) {
      return res.status(401).send('User not authenticated');
    }

    // Extract form data from req.body
    const { building, street, area, city, state, pincode, phone, paymentMethod } = req.body;

    // Combine address fields into a single string
    const address = `${building}, ${street}, ${area}, ${city}, ${state} - ${pincode}`;

    // Get current user info from req.session.user
    const userId = req.session.user.id;
    console.log(userId);

    // Format the order date and delivery date
    const orderDate = moment().format('YYYY-MM-DD');
    const deliveryDate = moment().add(4, 'days').format('YYYY-MM-DD');

    // Fetch the user's name from the users table
    const [userResult] = await db.query('SELECT name FROM users WHERE id = ?', [userId]);
    const userName = userResult[0].name; // Assuming 'name' field in users table
    console.log(userName);

    // Insert the order into the orders table
    const [orderResult] = await db.query(
      'INSERT INTO orders (user_id, user_name, address, phone, payment_method, order_date, delivery_date , status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [userId, userName, address, phone, paymentMethod, orderDate, deliveryDate, 'pending']
    );
    //const orderId = orderResult.insertId; // Get the generated order ID

    // Fetch cart details for the current user
    const [cartItems] = await db.query('SELECT product_id, quantity FROM cart WHERE user_id = ?', [userId]);

    // Prepare order confirmation data
    const orderDetails = [];

    for (let cartItem of cartItems) {
      const productId = cartItem.product_id;
      const quantity = cartItem.quantity;


      // Fetch product details
      const [productResult] = await db.query('SELECT name, price , image_url FROM products WHERE id = ?', [productId]);
      const productName = productResult[0].name;
      const price = productResult[0].price;

      // Add product details to the orderDetails array
      orderDetails.push({
        productId : productId,
        productName : productName,
        price : price,
        quantity : productResult[0].quantity,
        image: productResult[0].image_url
      });

      console.log(`Added product ${productName} to order_items for order ID:`);
      const orderId = orderResult.insertId; 

      await db.query(
        'INSERT INTO order_items (order_id, product_id, product_name, price, quantity) VALUES (?, ?, ?, ?, ?)',
        [ orderId, productId, productName, price, quantity]
      );
    }

    // Clear the cart after processing the items
    await db.query('DELETE FROM cart WHERE user_id = ?', [userId]);


    console.log('Cart cleared successfully');
    res.render('order-confirmation', {
      userName,
      address,
      phone,
      deliveryDate,
      orderDetails
    }); // You can redirect to a success page if needed

  } catch (err) {
    console.error('Error placing order:', err);
    res.status(500).send('Error placing order.');
  }

});
       
app.post('/cancel-order', async (req, res) => {
  const userId = req.session.user.id;  // Assuming the logged-in user is stored in the session
  const { orderId } = req.body;
  console.log(req.body);
  let message = ""; // Initialize message

  if (!orderId) {
      message = 'Order ID is missing.';
      return res.render('help', { message, userLoggedIn: true }); // Render with message
  }

  try {
      // Update the order status to 'cancelled' for the logged-in user
      const [result] = await db.query(
          'UPDATE orders SET status = ? WHERE id = ? AND user_id = ? AND status != "cancelled"',
          ['cancelled', orderId, userId]  // Ensuring the logged-in user is canceling their own order
      );

      // Check if the order was successfully updated
      if (result.affectedRows > 0) {
          message = `Order with ID ${orderId} has been successfully canceled.`;
      } else {
          message = `Order with ID ${orderId} could not be found or canceled.`;
      }

      // Render the response with the message
      res.render('help', { message, userLoggedIn: true });
  } catch (error) {
      console.error('Error updating order status:', error);
      message = 'Failed to cancel the order. Please try again.';
      res.render('help', { message, userLoggedIn: true });
  }
});




    // Start the server
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Error connecting to the database:", err);
  });
