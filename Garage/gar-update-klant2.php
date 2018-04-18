<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="author " content="Espen Solstad">
    <meta charset="UTF-8">
    <title>GCU</title>
</head>
<body>
    <h1>Garage Customer Updater</h1>
    <p>
        This form is used to update customer data.
    </p>
    <?php
    // klantid uit het formulier halen ----------------------------
    $klantid = $_POST["klantidvak"];

    // klantgegevens uit de tabel halen ---------------------------
    require_once "gar-connect.php";

    $klanten = $conn->prepare("
select  klantid,
        klantnaam,
        klantadres,
        klantpostcode,
        klantplaats
from    klant
where   klantid = :klantid
");
    $klanten->execute(["klantid" => $klantid]);

    // klantgegevens in een nieuw formulier laten zien ---------------
    echo "<form action='gar-update-klant3.php' method='post'>";
    foreach($klanten as $klant)
    {
        // klantid mag niet gewijzigd worden
        echo " klantid:" . $klant["klantid"];
        echo " <input type='hidden' name='klantidvak' ";
        echo " value=' " . $klant["klantid"] . " '> <br /> ";

        echo " klantnaam: <input type='text' ";
        echo " name  = 'klantnaamvak' ";
        echo " value = '" .$klant["klantnaam"]. "' ";
        echo " > <br />";

        echo " klantadres: <input type='text' ";
        echo " name  = 'klantadresvak' ";
        echo " value = '" .$klant["klantadres"]. "' ";
        echo " > <br />";

        echo " klantpostcode: <input type='text' ";
        echo " name  = 'klantpostcodevak' ";
        echo " value = '" .$klant["klantpostcode"]. "' ";
        echo " > <br />";

        echo " klantplaats: <input type='text' ";
        echo " name  = 'klantplaatsvak' ";
        echo " value = '" .$klant["klantplaats"]. "' ";
        echo " > <br />";
    }
    echo "<input type='submit'>";
    echo "</form>";

    // er moet eigenlijk nog gecontroleerd worden op een bestaand klantid
    ?>
</body>
</html>