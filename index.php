<?php
session_start();

if(!isset($_SESSION['user'])){
   header("location: login.php");
}else{
   header("location: dashboard.php");
}