import React from 'react';
import Navbar from "./Navbar";
import CheckingForInternetConnectivity from "../misc/CheckingForInternetConnectivity";
import Header from '../Home/Header';
import {Outlet} from "react-router-dom";

const PageTemplate = (props: any) => {
    return (
        <div>
            <Navbar/>
            <div className="w-full bg-pageBackGroundColor text-center">
                <Header/>
            </div>
            <Outlet/>
            <CheckingForInternetConnectivity/>
        </div>
    );
}

export default PageTemplate;
