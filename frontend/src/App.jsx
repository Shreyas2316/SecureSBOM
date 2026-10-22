import React from "react";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import LandingPage from "./landing/LandingPage";
import ScannerApp from "./app/ScannerApp";
import { pageWipeVariants } from "./lib/motion";

function AnimatedRoutes() {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route
          path="/"
          element={
            <motion.div
              variants={pageWipeVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              style={{ width: "100%", minHeight: "100vh" }}
            >
              <LandingPage />
            </motion.div>
          }
        />
        <Route
          path="/app/*"
          element={
            <motion.div
              variants={pageWipeVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              style={{ width: "100%", minHeight: "100vh" }}
            >
              <ScannerApp />
            </motion.div>
          }
        />
        <Route
          path="*"
          element={
            <motion.div
              variants={pageWipeVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              style={{ width: "100%", minHeight: "100vh" }}
            >
              <LandingPage />
            </motion.div>
          }
        />
      </Routes>
    </AnimatePresence>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AnimatedRoutes />
    </BrowserRouter>
  );
}
