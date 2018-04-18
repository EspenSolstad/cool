<!DOCTYPE html>
<html lang="en">
<head>
    <title>GDD</title>
</head>
<body>
<h1>Garage Data Deletor</h1>
<p>
    This form let's you delete Customer ID's.
</p>
<form action="gar-delete-klant2.php" method="post">
    What customer ID do you want to delete?
    <input type="text" name="klantidvak"> <br />
    <input type="submit">
</form>
<?php
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>