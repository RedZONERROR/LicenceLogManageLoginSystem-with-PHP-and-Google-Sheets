<?php session_start(); ?>
<!DOCTYPE html>
<html lang="en">
<head>
   <meta charset="UTF-8">
   <meta http-equiv="X-UA-Compatible" content="IE=edge">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <link rel="stylesheet" href="style.css">
   <title>Login page</title>
</head>
<body>
   <div class="formContainer">
      <form method="post" action="login_action.php">
         <h2 class="title">Login</h2>
         <div class="tip">
            Login to your account using email and password
         </div>
         <?php
         if(isset($_SESSION['error'])){
            echo "<div class='errorMsg'>{$_SESSION['error']}</div>";
            unset($_SESSION['error']);
         }
         ?>
         <label for="email">Email</label>
         <input type="text" name="email" autocomplete="off">
         <label for="password">Password</label>
         <input type="password" name="password">
         <input type="submit" value="LOGIN">
      </form>
      <div class="link">
         Don't have an account yet? <a href="signup.php">Sign up</a>
      </div>
   </div>
</body>
</html>