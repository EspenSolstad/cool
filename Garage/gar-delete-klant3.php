<!DOCTYPE html>
<html lang="en">
<head>
    <title>GDD</title>
</head>
<body>
<h1>Garage Data Deletor</h1>
<p>
    Here you can Delete your Customer ID.
</p>
<?php
// gegevens  uit het formulier halen -----------------------
$klantid      = $_POST["klantidvak"];
$verwijderen  = $_POST["verwijdervak"];

// klantgegevens verwijderen -------------------------------
if($verwijderen)
{
    require_once "gar-connect.php";

    $sql = $conn->prepare("
    delete from klant
    where klantid = :klantid
    ");

    $sql->execute(["klantid" => $klantid]);

    echo "All data has been deleted. <br />";
}
else {
    echo "Something went wrong, please try again. <br />";
}
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>