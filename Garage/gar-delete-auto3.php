<!DOCTYPE html>
<html lang="en">
<head>
    <title>gar-delete-auto3.php</title>
</head>
<body>
<h1>garage delete auto 3</h1>
<p>
    Op auto gegevens zoeken uit de
    tabel auto's van de database garage
    zodat ze verwijderd kunnen worden.
</p>
<?php
// gegevens  uit het formulier halen -----------------------
$autokenteken      = $_POST["autokentekenvak"];
$verwijderen  = $_POST["verwijdervak"];

// klantgegevens verwijderen -------------------------------
if($verwijderen)
{
    require_once "gar-connect.php";

    $sql = $conn->prepare("
    delete from auto
    where autokenteken = :autokenteken
    ");

    $sql->execute(["autokenteken" => $autokenteken]);

    echo "All data has been deleted. <br />";
}
else {
    echo "Something went wrong try again.<br />";
}
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>