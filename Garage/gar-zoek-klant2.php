<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="author " content="Espen Solstad">
    <meta charset="UTF-8">
    <title>GCS</title>
</head>
<body>
    <h1>Garage Customer Searcher</h1>
    <p>
        Searched for a customer using the CustomerID.
    </p>
    <?php
    $klantid = $_POST["klantidvak"];

    require_once "gar-connect.php";

    $sql = $conn->prepare("
                                    select  klantid,
                                                klantnaam,
                                                klantadres,
                                                klantpostcode,
                                                klantplaats
                                        from    klant
                                        where   klantid = :klantid
                                      ");
    $sql->execute(["klantid" => $klantid]);


    echo "<table>";
    foreach ($sql as $rij)
    {
        echo "<tr>";
            echo "<td>"  . $rij["klantid"]       . "</td>";
            echo "<td>"  . $rij["klantnaam"]     . "</td>";
            echo "<td>"  . $rij["klantadres"]    . "</td>";
            echo "<td>"  . $rij["klantpostcode"] . "</td>";
            echo "<td>"  . $rij["klantplaats"]   . "</td>";
        echo "</tr>";
    }
    echo "</table>";
    echo "<a href='gar-menu.php'>Back to the GDM</a>";
    ?>
</body>
</html>