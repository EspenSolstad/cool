<!DOCTYPE html>
<html lang="nl">
    <head>
        <title>GCS</title>
    </head>
<body>
    <h1>Garage Customer Searcher</h1>
    <p>
        This form searches for the CustomerID.
    </p>
    <form action="gar-zoek-klant2.php" method="post">
        What Customer ID do you wish to find?
        <input type="text" name="klantidvak">  <br />
        <input type="submit">
    </form>
</body>
    <?php
    echo "<a href='gar-menu.php'>Back to the GDM</a>";
    ?>
</html>