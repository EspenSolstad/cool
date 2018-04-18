<!DOCTYPE html>
<html lang="en">
<head>
    <title>GCU</title>
</head>
    <body>
        <h1>Garage Customer Updater</h1>
        <p>
            This form is used to update Customer data.
        </p>
        <form action="gar-update-klant2.php" method="post">
            What Customer ID do you wish to update?
            <input type="text" name="klantidvak">  <br />
            <input type="submit">
        </form>
        <?php
        echo "<a href='gar-menu.php'>Back to the GDM</a>";
        ?>
    </body>
</html>